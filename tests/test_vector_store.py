"""
Tests for the InMemoryVectorStore (demo mode).
"""
from src.context.vector_store import InMemoryVectorStore


class TestInMemoryVectorStore:
    def test_index_and_count(self):
        store = InMemoryVectorStore()
        store.index("doc1", "FastAPI payment webhook route")
        assert store.count() == 1

    def test_search_returns_relevant_results(self):
        store = InMemoryVectorStore()
        store.index("doc-payments", "payment webhook stripe HMAC signature verification")
        store.index("doc-users", "user authentication JWT token OAuth2")
        store.index("doc-orders", "order management inventory stock")

        results = store.search("payment stripe webhook", top_k=2)
        assert len(results) >= 1
        assert results[0]["id"] == "doc-payments"

    def test_search_returns_empty_for_no_match(self):
        store = InMemoryVectorStore()
        store.index("doc1", "completely unrelated document about shipping")
        results = store.search("quantum physics nuclear reactor", top_k=5)
        assert results == []

    def test_top_k_limits_results(self):
        store = InMemoryVectorStore()
        for i in range(10):
            store.index(f"doc-{i}", f"api endpoint route fastapi handler {i}")
        results = store.search("api endpoint route", top_k=3)
        assert len(results) <= 3

    def test_metadata_preserved(self):
        store = InMemoryVectorStore()
        store.index("doc1", "some content", metadata={"type": "architecture", "version": "2"})
        results = store.search("some content", top_k=1)
        assert results[0]["metadata"]["type"] == "architecture"
