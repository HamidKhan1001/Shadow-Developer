"""
Code Monitor — Static Security Scanner

Walks real Python source files and highlights suspicious / security-relevant
code patterns with exact file paths, line numbers, and severity ratings.

This is what makes Shadow Developer a *live* monitoring tool, not just a
prompt auditor — it can scan your actual codebase on demand.
"""
import ast
import re
import logging
from pathlib import Path
from dataclasses import dataclass, field, asdict
from typing import Any

logger = logging.getLogger(__name__)


# ------------------------------------------------------------------ #
# Data models                                                          #
# ------------------------------------------------------------------ #

@dataclass
class CodeFinding:
    """A single security finding in source code."""
    severity: str          # critical | high | medium | low | info
    category: str          # injection | auth | crypto | secrets | config | owasp
    rule_id: str           # machine-readable rule identifier
    file: str              # relative file path
    line: int              # 1-indexed line number
    col: int               # 1-indexed column
    snippet: str           # the offending line of code (stripped)
    description: str
    remediation: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ScanResult:
    """Aggregated result of scanning one or more files."""
    scanned_files: int = 0
    total_lines: int = 0
    findings: list[CodeFinding] = field(default_factory=list)
    summary: dict[str, int] = field(default_factory=dict)

    def add(self, finding: CodeFinding) -> None:
        self.findings.append(finding)
        self.summary[finding.severity] = self.summary.get(finding.severity, 0) + 1

    def to_dict(self) -> dict[str, Any]:
        return {
            "scanned_files": self.scanned_files,
            "total_lines": self.total_lines,
            "total_findings": len(self.findings),
            "summary": self.summary,
            "findings": [f.to_dict() for f in self.findings],
        }


# ------------------------------------------------------------------ #
# Regex-based rules (line-by-line)                                    #
# ------------------------------------------------------------------ #

# Each entry: (rule_id, severity, category, regex_pattern, description, remediation)
REGEX_RULES: list[tuple[str, str, str, str, str, str]] = [
    # --- Injection ---
    (
        "INJ-001", "critical", "injection",
        r"cursor\.execute\s*\(\s*[fF]['\"]|cursor\.execute\s*\(\s*.*%.*['\"]",
        "Raw SQL via cursor.execute with string formatting — SQL Injection risk (OWASP A03)",
        "Use parameterized queries: cursor.execute('SELECT * FROM t WHERE id=%s', (val,))",
    ),
    (
        "INJ-002", "critical", "injection",
        r"execute\s*\(\s*f['\"]SELECT|execute\s*\(\s*f['\"]INSERT|execute\s*\(\s*f['\"]UPDATE|execute\s*\(\s*f['\"]DELETE",
        "f-string SQL query passed to execute() — SQL Injection (OWASP A03)",
        "Use SQLAlchemy ORM or parameterized queries.",
    ),
    (
        "INJ-003", "high", "injection",
        r"subprocess\.(call|run|Popen)\s*\(.*shell\s*=\s*True",
        "subprocess called with shell=True — Command Injection risk (OWASP A03)",
        "Pass command as a list: subprocess.run(['cmd', arg]) without shell=True.",
    ),
    (
        "INJ-004", "high", "injection",
        r"\beval\s*\(|__import__\s*\(",
        "eval() or __import__() detected — arbitrary code execution risk",
        "Avoid eval(); use ast.literal_eval() for safe data parsing.",
    ),
    (
        "INJ-005", "high", "injection",
        r"\bos\.system\s*\(",
        "os.system() call detected — prefer subprocess with a list of args",
        "Replace with subprocess.run(['cmd', arg], capture_output=True).",
    ),
    # --- Authentication / Authorisation ---
    (
        "AUTH-001", "critical", "auth",
        r"verify\s*=\s*False",
        "SSL certificate verification disabled — man-in-the-middle risk (OWASP A07)",
        "Remove verify=False; use a proper CA bundle or self-signed cert config.",
    ),
    (
        "AUTH-002", "high", "auth",
        r"jwt\.decode\s*\(.*algorithms\s*=\s*\[\s*['\"]none['\"]",
        "JWT decoded with algorithm 'none' — auth bypass vulnerability",
        "Always specify a strong algorithm: algorithms=['HS256'] and validate signature.",
    ),
    (
        "AUTH-003", "high", "auth",
        r"#\s*(no auth|skip auth|TODO.*auth|FIXME.*auth)",
        "Comment suggests auth check is missing or skipped",
        "Implement proper authentication before this route goes to production.",
    ),
    (
        "AUTH-004", "medium", "auth",
        r"allow_origins\s*=\s*\[?\s*['\"][*]['\"]",
        "CORS allow_origins='*' — overly permissive cross-origin policy",
        "Restrict origins to known domains in production.",
    ),
    # --- Cryptography ---
    (
        "CRYPTO-001", "critical", "crypto",
        r"\bmd5\s*\(|\bhashlib\.md5\b",
        "MD5 hash detected — cryptographically broken (OWASP A02)",
        "Use SHA-256 or better: hashlib.sha256(data).hexdigest()",
    ),
    (
        "CRYPTO-002", "high", "crypto",
        r"\bsha1\s*\(|\bhashlib\.sha1\b",
        "SHA-1 hash detected — deprecated for security use (OWASP A02)",
        "Use SHA-256 or better for any security-sensitive hashing.",
    ),
    (
        "CRYPTO-003", "high", "crypto",
        r"random\.random\(\)|random\.randint\(|random\.choice\(",
        "Non-cryptographic random used — predictable values in security context",
        "Use secrets.token_hex() or secrets.choice() for security-sensitive randomness.",
    ),
    # --- Secrets / Credentials ---
    (
        "SEC-001", "critical", "secrets",
        r"""(?i)(password|passwd|pwd)\s*=\s*['\"][^'"]{4,}['"]""",
        "Hardcoded password string detected in source code",
        "Move credentials to environment variables or a secrets manager.",
    ),
    (
        "SEC-002", "critical", "secrets",
        r"""(?i)(api[_-]?key|apikey|secret[_-]?key)\s*=\s*['\"][A-Za-z0-9\-_]{8,}['"]""",
        "Hardcoded API key or secret detected in source code",
        "Use os.getenv('API_KEY') and store secrets in .env or AWS Secrets Manager.",
    ),
    (
        "SEC-003", "high", "secrets",
        r"""(?i)(token|auth[_-]?token|bearer)\s*=\s*['\"][A-Za-z0-9\.\-_]{20,}['"]""",
        "Hardcoded auth token detected in source code",
        "Load tokens from environment variables at runtime.",
    ),
    (
        "SEC-004", "high", "secrets",
        r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----",
        "Private key embedded in source file",
        "Remove the key immediately. Store in a secrets vault, never in source.",
    ),
    # --- Dangerous Config ---
    (
        "CFG-001", "high", "config",
        r"DEBUG\s*=\s*True|debug\s*=\s*True",
        "Debug mode enabled — may expose stack traces and internal details in production",
        "Set DEBUG=False in production; control via APP_ENV environment variable.",
    ),
    (
        "CFG-002", "medium", "config",
        r"SECRET_KEY\s*=\s*['\"][\w\-]{1,20}['\"]",
        "Weak or short SECRET_KEY detected",
        "Generate a strong secret: python -c \"import secrets; print(secrets.token_hex(32))\"",
    ),
    (
        "CFG-003", "medium", "config",
        r"host\s*=\s*['\"]0\.0\.0\.0['\"]",
        "Server bound to 0.0.0.0 — exposed on all interfaces",
        "Bind to 127.0.0.1 in development; use a reverse proxy (nginx) in production.",
    ),
    # --- Deserialization ---
    (
        "DESER-001", "critical", "injection",
        r"\bpickle\.loads?\s*\(|\bpickle\.load\s*\(",
        "pickle.load(s) from untrusted input — arbitrary code execution (OWASP A08)",
        "Use JSON or MessagePack for serialization. Never unpickle untrusted data.",
    ),
    (
        "DESER-002", "high", "injection",
        r"\byaml\.load\s*\([^,)]+\)",
        "yaml.load() without Loader — unsafe deserialization risk",
        "Use yaml.safe_load() instead.",
    ),
    # --- Path traversal ---
    (
        "PATH-001", "high", "injection",
        r"open\s*\(\s*.*\+|open\s*\(\s*f['\"]",
        "open() called with dynamic/user-controlled path — path traversal risk (OWASP A01)",
        "Validate and sanitize file paths; use pathlib.Path.resolve() and check against a safe root.",
    ),
]


# ------------------------------------------------------------------ #
# AST-based rules                                                      #
# ------------------------------------------------------------------ #

def _ast_check_try_except_pass(tree: ast.AST, filepath: str, lines: list[str]) -> list[CodeFinding]:
    """Flag bare except: pass — swallows errors silently."""
    findings = []
    for node in ast.walk(tree):
        if isinstance(node, ast.ExceptHandler):
            if node.type is None:  # bare except
                body = node.body
                if len(body) == 1 and isinstance(body[0], ast.Pass):
                    line_no = node.lineno
                    snippet = lines[line_no - 1].strip() if line_no <= len(lines) else ""
                    findings.append(CodeFinding(
                        severity="medium",
                        category="config",
                        rule_id="CFG-004",
                        file=filepath,
                        line=line_no,
                        col=node.col_offset + 1,
                        snippet=snippet,
                        description="Bare 'except: pass' swallows all exceptions silently — hides security errors",
                        remediation="Catch specific exceptions and log them: except Exception as e: logger.error(e)",
                    ))
    return findings


def _ast_check_assert_auth(tree: ast.AST, filepath: str, lines: list[str]) -> list[CodeFinding]:
    """Flag assert used for auth/security checks — strips in optimized mode."""
    findings = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Assert):
            line_no = node.lineno
            snippet = lines[line_no - 1].strip() if line_no <= len(lines) else ""
            if re.search(r"(auth|permission|role|admin|token|user)", snippet, re.IGNORECASE):
                findings.append(CodeFinding(
                    severity="high",
                    category="auth",
                    rule_id="AUTH-005",
                    file=filepath,
                    line=line_no,
                    col=node.col_offset + 1,
                    snippet=snippet,
                    description="assert used for security/auth check — disabled with python -O flag",
                    remediation="Replace with explicit if/raise: if not condition: raise PermissionError(...)",
                ))
    return findings


# ------------------------------------------------------------------ #
# Main scanner                                                         #
# ------------------------------------------------------------------ #

class CodeScanner:
    """
    Scans Python source files for security issues, suspicious patterns,
    and highlighted code that needs review.
    """

    # Files/dirs to always skip
    SKIP_DIRS = {".git", "__pycache__", "venv", "env", ".venv", "node_modules", "dist", "build"}
    SKIP_FILES = {"*.pyc", "*.pyo"}

    def scan_file(self, filepath: str, relative_to: str = "") -> ScanResult:
        """Scan a single Python file."""
        result = ScanResult()
        path = Path(filepath)
        if not path.exists() or not path.suffix == ".py":
            return result

        try:
            source = path.read_text(encoding="utf-8")
        except OSError as exc:
            logger.warning("Cannot read %s: %s", filepath, exc)
            return result

        lines = source.splitlines()
        display_path = str(path.relative_to(relative_to)) if relative_to else str(path)

        result.scanned_files = 1
        result.total_lines = len(lines)

        # Regex rules
        for line_no, line in enumerate(lines, 1):
            for rule_id, severity, category, pattern, description, remediation in REGEX_RULES:
                if re.search(pattern, line):
                    result.add(CodeFinding(
                        severity=severity,
                        category=category,
                        rule_id=rule_id,
                        file=display_path,
                        line=line_no,
                        col=1,
                        snippet=line.strip()[:120],
                        description=description,
                        remediation=remediation,
                    ))

        # AST rules
        try:
            tree = ast.parse(source)
            for finding in _ast_check_try_except_pass(tree, display_path, lines):
                result.add(finding)
            for finding in _ast_check_assert_auth(tree, display_path, lines):
                result.add(finding)
        except SyntaxError:
            pass  # already counted lines, just skip AST pass

        return result

    def scan_directory(self, root_path: str, extensions: tuple[str, ...] = (".py",)) -> ScanResult:
        """Recursively scan all matching files in a directory."""
        root = Path(root_path)
        combined = ScanResult()

        for path in sorted(root.rglob("*")):
            # Skip hidden dirs and known non-source dirs
            if any(part in self.SKIP_DIRS for part in path.parts):
                continue
            if path.is_file() and path.suffix in extensions:
                file_result = self.scan_file(str(path), relative_to=root_path)
                combined.scanned_files += file_result.scanned_files
                combined.total_lines += file_result.total_lines
                for f in file_result.findings:
                    combined.add(f)

        logger.info(
            "Scan complete: %d files, %d lines, %d findings",
            combined.scanned_files, combined.total_lines, len(combined.findings),
        )
        return combined

    def scan_code_snippet(self, code: str, filename: str = "<snippet>") -> ScanResult:
        """Scan an inline code snippet (no file required)."""
        import tempfile
        result = ScanResult()
        lines = code.splitlines()
        result.total_lines = len(lines)
        result.scanned_files = 1

        for line_no, line in enumerate(lines, 1):
            for rule_id, severity, category, pattern, description, remediation in REGEX_RULES:
                if re.search(pattern, line):
                    result.add(CodeFinding(
                        severity=severity,
                        category=category,
                        rule_id=rule_id,
                        file=filename,
                        line=line_no,
                        col=1,
                        snippet=line.strip()[:120],
                        description=description,
                        remediation=remediation,
                    ))
        try:
            tree = ast.parse(code)
            for finding in _ast_check_try_except_pass(tree, filename, lines):
                result.add(finding)
            for finding in _ast_check_assert_auth(tree, filename, lines):
                result.add(finding)
        except SyntaxError:
            pass

        return result
