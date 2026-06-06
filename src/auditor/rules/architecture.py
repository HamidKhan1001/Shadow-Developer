"""
Architectural drift rules.

These rules compare the incoming feature prompt against the parsed
GlobalContext (API endpoints, models, dependencies) to detect collisions
and breaking changes before any code is written.
"""
import re
from typing import TYPE_CHECKING

from ...interceptor.models import ConflictDetail
from ...context.parser import GlobalContext

if TYPE_CHECKING:
    pass


def check_api_drift(prompt: str, ctx: GlobalContext) -> list[ConflictDetail]:
    """
    Detect if the prompt proposes a path that already exists with a
    different HTTP method — a classic API drift scenario.
    """
    conflicts: list[ConflictDetail] = []
    # Extract path patterns from the prompt (e.g. /payments/webhook)
    proposed_paths = re.findall(r"/[\w/{}:_-]+", prompt)
    existing = {e.path: e.method for e in ctx.endpoints}

    for proposed in proposed_paths:
        if proposed in existing:
            existing_method = existing[proposed]
            # If the prompt implies a different HTTP verb, flag it
            prompt_lower = prompt.lower()
            inferred_methods = []
            for verb in ("post", "put", "patch", "delete", "get"):
                if verb in prompt_lower:
                    inferred_methods.append(verb.upper())

            for inferred in inferred_methods:
                if inferred != existing_method:
                    conflicts.append(ConflictDetail(
                        severity="high",
                        category="api_drift",
                        description=(
                            f"Path '{proposed}' already registered as {existing_method}. "
                            f"New feature implies {inferred} — this will cause a routing collision."
                        ),
                        affected_component=f"route:{proposed}",
                        remediation=(
                            f"Use a versioned path (e.g. /v2{proposed}) or "
                            "confirm the existing route should be overridden."
                        ),
                    ))
    return conflicts


def check_schema_collision(prompt: str, ctx: GlobalContext) -> list[ConflictDetail]:
    """
    Warn if the prompt introduces a model/table name that already exists.
    """
    conflicts: list[ConflictDetail] = []
    for model_name in ctx.models:
        pattern = rf"\b{re.escape(model_name)}\b"
        if re.search(pattern, prompt, re.IGNORECASE):
            conflicts.append(ConflictDetail(
                severity="medium",
                category="schema_collision",
                description=(
                    f"Model '{model_name}' already exists in the codebase. "
                    "Adding fields or changing its shape may cause migration conflicts."
                ),
                affected_component=f"model:{model_name}",
                remediation=(
                    "Create a migration script with Alembic and ensure backward-compatible "
                    "schema changes. Consider a new model if the structure diverges significantly."
                ),
            ))
    return conflicts


def check_dependency_conflict(prompt: str, ctx: GlobalContext) -> list[ConflictDetail]:
    """
    Warn if the prompt mentions a library that appears in the dependency tree
    but could conflict with an existing pinned version.
    """
    conflicts: list[ConflictDetail] = []
    version_mentions = re.findall(r"([\w-]+)[=><~!]+(\d[\d.]*)", prompt)
    for lib, version in version_mentions:
        pinned = ctx.dependencies.get(lib)
        if pinned and pinned != version:
            conflicts.append(ConflictDetail(
                severity="medium",
                category="dependency",
                description=(
                    f"Prompt requests '{lib}=={version}' but codebase pins '{lib}=={pinned}'. "
                    "Version mismatch could break transitive dependencies."
                ),
                affected_component=f"dependency:{lib}",
                remediation=(
                    f"Audit changelog between {pinned} and {version}. "
                    "Update requirements.txt and run the full test suite before merging."
                ),
            ))
    return conflicts
