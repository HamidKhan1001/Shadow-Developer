"""
Vector Context Store

Wraps Amazon Bedrock (for embeddings) and Amazon OpenSearch Serverless
(for vector storage and similarity search).  In demo/local mode, falls
back to a simple in-memory store so the rest of the system works without
AWS credentials.
"""
import json
import logging
from typing import Any

logger = logging.getLogger(__name__)


class InMemoryVectorStore:
    """
    Lightweight in-memory fallback — no AWS required.
    Stores documents as plain dicts and does keyword-based retrieval.
    """

    def __init__(self) -> None:
        self._store: list[dict[str, Any]] = []

    def index(self, doc_id: str, content: str, metadata: dict | None = None) -> None:
        self._store.append({
            "id": doc_id,
            "content": content,
            "metadata": metadata or {},
        })
        logger.debug("InMemoryVectorStore: indexed doc_id=%s", doc_id)

    def search(self, query: str, top_k: int = 5) -> list[dict[str, Any]]:
        """Naive keyword overlap ranking for demo purposes."""
        query_terms = set(query.lower().split())
        scored: list[tuple[float, dict]] = []
        for doc in self._store:
            terms = set(doc["content"].lower().split())
            overlap = len(query_terms & terms)
            if overlap:
                scored.append((overlap, doc))
        scored.sort(key=lambda x: x[0], reverse=True)
        return [doc for _, doc in scored[:top_k]]

    def count(self) -> int:
        return len(self._store)


class VectorStore:
    """
    Production-grade store backed by Amazon Bedrock + OpenSearch Serverless.
    Falls back to InMemoryVectorStore when the endpoint is not configured.
    """

    def __init__(self, endpoint: str, index: str, region: str = "us-east-1") -> None:
        self._endpoint = endpoint
        self._index = index
        self._region = region
        self._memory = InMemoryVectorStore()
        self._os_client = None
        self._bedrock_client = None

        if "localhost" not in endpoint and endpoint:
            self._init_aws_clients()

    def _init_aws_clients(self) -> None:
        try:
            import boto3
            from opensearchpy import OpenSearch, RequestsHttpConnection
            from requests_aws4auth import AWS4Auth

            credentials = boto3.Session().get_credentials()
            awsauth = AWS4Auth(
                credentials.access_key,
                credentials.secret_key,
                self._region,
                "aoss",
                session_token=credentials.token,
            )
            self._os_client = OpenSearch(
                hosts=[{"host": self._endpoint.replace("https://", ""), "port": 443}],
                http_auth=awsauth,
                use_ssl=True,
                verify_certs=True,
                connection_class=RequestsHttpConnection,
            )
            self._bedrock_client = boto3.client("bedrock-runtime", region_name=self._region)
            logger.info("VectorStore: connected to OpenSearch @ %s", self._endpoint)
        except Exception as exc:  # pragma: no cover
            logger.warning("VectorStore: AWS init failed (%s) — using in-memory fallback", exc)

    def _embed(self, text: str) -> list[float]:
        """Get embedding from Amazon Bedrock Titan."""
        if not self._bedrock_client:
            return []
        body = json.dumps({"inputText": text})
        response = self._bedrock_client.invoke_model(
            modelId="amazon.titan-embed-text-v1",
            body=body,
            contentType="application/json",
            accept="application/json",
        )
        return json.loads(response["body"].read())["embedding"]

    def index(self, doc_id: str, content: str, metadata: dict | None = None) -> None:
        if self._os_client:
            vector = self._embed(content)
            doc = {"content": content, "metadata": metadata or {}, "vector": vector}
            self._os_client.index(index=self._index, id=doc_id, body=doc)
        else:
            self._memory.index(doc_id, content, metadata)

    def search(self, query: str, top_k: int = 5) -> list[dict[str, Any]]:
        if self._os_client:
            vector = self._embed(query)
            knn_query = {
                "size": top_k,
                "query": {"knn": {"vector": {"vector": vector, "k": top_k}}},
            }
            resp = self._os_client.search(index=self._index, body=knn_query)
            return [hit["_source"] for hit in resp["hits"]["hits"]]
        return self._memory.search(query, top_k)
