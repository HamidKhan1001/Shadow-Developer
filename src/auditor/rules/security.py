"""
OWASP-aligned security rules applied to every incoming feature prompt.

Each rule is a callable that receives the prompt text and returns a list of
ConflictDetail objects (empty list = no violation found).
"""
import re
from typing import Callable

from ...interceptor.models import ConflictDetail


RuleFunc = Callable[[str], list[ConflictDetail]]


def _rule_sql_injection(prompt: str) -> list[ConflictDetail]:
    """Flag prompts that mention raw SQL queries without parameterisation."""
    keywords = re.findall(r"\b(raw sql|execute\(|cursor\.execute|f\"select|f'select)\b", prompt, re.IGNORECASE)
    if keywords:
        return [ConflictDetail(
            severity="critical",
            category="security",
            description="Prompt references raw SQL execution. Risk of SQL Injection (OWASP A03:2021).",
            affected_component="database layer",
            remediation="Use an ORM (SQLAlchemy) or parameterized queries instead of string-interpolated SQL.",
        )]
    return []


def _rule_auth_bypass(prompt: str) -> list[ConflictDetail]:
    """Flag prompts that skip authentication or authorisation checks."""
    patterns = [r"skip\w* auth", r"no auth", r"bypass.*auth", r"unauthenticated", r"public.*admin", r"admin.*endpoint.*bypass", r"bypass.*for.*internal"]
    for pattern in patterns:
        if re.search(pattern, prompt, re.IGNORECASE):
            return [ConflictDetail(
                severity="critical",
                category="security",
                description=f"Prompt matches pattern '{pattern}' — potential auth bypass (OWASP A01:2021).",
                affected_component="auth middleware",
                remediation="Ensure all sensitive endpoints are protected by JWT/OAuth2 dependency injection.",
            )]
    return []


def _rule_secret_in_prompt(prompt: str) -> list[ConflictDetail]:
    """Flag accidental secrets embedded in the prompt."""
    patterns = [r"api[_-]?key\s*=\s*\S+", r"password\s*=\s*\S+", r"secret\s*=\s*\S+"]
    for pattern in patterns:
        match = re.search(pattern, prompt, re.IGNORECASE)
        if match:
            return [ConflictDetail(
                severity="high",
                category="security",
                description="Potential secret/credential detected in prompt text.",
                affected_component="prompt payload",
                remediation="Remove credentials from prompts; use environment variables or AWS Secrets Manager.",
            )]
    return []


def _rule_webhook_missing_signature_check(prompt: str) -> list[ConflictDetail]:
    """Flag webhook implementations without HMAC signature verification."""
    if re.search(r"webhook", prompt, re.IGNORECASE):
        if not re.search(r"(signature|hmac|verify|secret|x-hub-signature)", prompt, re.IGNORECASE):
            return [ConflictDetail(
                severity="high",
                category="security",
                description="Webhook route detected but no mention of signature verification.",
                affected_component="webhook handler",
                remediation=(
                    "Always validate incoming webhook payloads using HMAC-SHA256 "
                    "signature verification against a shared secret."
                ),
            )]
    return []


def _rule_rate_limiting(prompt: str) -> list[ConflictDetail]:
    """Warn when a new public endpoint is added without rate limiting mention."""
    has_endpoint = re.search(r"\b(route|endpoint|api)\b", prompt, re.IGNORECASE)
    has_rate_limit = re.search(r"rate.?limit", prompt, re.IGNORECASE)
    if has_endpoint and not has_rate_limit:
        return [ConflictDetail(
            severity="medium",
            category="security",
            description="New endpoint added without mention of rate limiting.",
            affected_component="API gateway",
            remediation="Add slowapi or AWS WAF rate limiting to prevent abuse.",
        )]
    return []


# Ordered list of all active security rules
SECURITY_RULES: list[RuleFunc] = [
    _rule_sql_injection,
    _rule_auth_bypass,
    _rule_secret_in_prompt,
    _rule_webhook_missing_signature_check,
    _rule_rate_limiting,
]
