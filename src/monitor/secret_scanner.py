"""
Secret & Environment Scanner

Scans files (including .env, config files, source code) for leaked
credentials, hardcoded secrets, and sensitive values that should never
be committed to version control.

Also validates that .gitignore properly excludes sensitive files.
"""
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
class SecretFinding:
    """A single leaked secret or misconfigured env finding."""
    severity: str       # critical | high | medium | low
    type: str           # api_key | password | token | private_key | connection_string | env_exposure
    file: str
    line: int
    variable: str       # the variable/key name (never the value)
    description: str
    remediation: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class GitignoreReport:
    """Report on .gitignore completeness."""
    found: bool = False
    missing_patterns: list[str] = field(default_factory=list)
    present_patterns: list[str] = field(default_factory=list)
    is_sufficient: bool = False

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class SecretScanResult:
    """Full result of a secret scan."""
    scanned_files: int = 0
    findings: list[SecretFinding] = field(default_factory=list)
    gitignore_report: GitignoreReport = field(default_factory=GitignoreReport)
    env_files_found: list[str] = field(default_factory=list)
    exposed_env_files: list[str] = field(default_factory=list)  # .env files NOT in .gitignore

    def to_dict(self) -> dict[str, Any]:
        return {
            "scanned_files": self.scanned_files,
            "total_findings": len(self.findings),
            "findings": [f.to_dict() for f in self.findings],
            "gitignore_report": self.gitignore_report.to_dict(),
            "env_files_found": self.env_files_found,
            "exposed_env_files": self.exposed_env_files,
        }


# ------------------------------------------------------------------ #
# Secret detection patterns                                            #
# Each: (type, severity, key_pattern, value_pattern, description)     #
# We only capture the KEY, never log the value                        #
# ------------------------------------------------------------------ #

SECRET_PATTERNS: list[tuple[str, str, str, str]] = [
    # Generic high-entropy secrets
    (
        "api_key", "critical",
        r"(?i)(api[_-]?key|apikey|x[_-]?api[_-]?key)\s*[=:]\s*",
        r"['\"]?[A-Za-z0-9\-_]{16,}['\"]?",
    ),
    (
        "password", "critical",
        r"(?i)(password|passwd|pwd|pass)\s*[=:]\s*",
        r"['\"][^'\"]{4,}['\"]",
    ),
    (
        "secret_key", "critical",
        r"(?i)(secret[_-]?key|secretkey|app[_-]?secret)\s*[=:]\s*",
        r"['\"]?[A-Za-z0-9\-_]{8,}['\"]?",
    ),
    (
        "token", "high",
        r"(?i)(auth[_-]?token|access[_-]?token|bearer[_-]?token|jwt[_-]?secret)\s*[=:]\s*",
        r"['\"]?[A-Za-z0-9\.\-_]{20,}['\"]?",
    ),
    (
        "aws_key", "critical",
        r"(?i)(aws[_-]?access[_-]?key[_-]?id|aws[_-]?secret[_-]?access[_-]?key)\s*[=:]\s*",
        r"['\"]?[A-Za-z0-9\/+]{16,}['\"]?",
    ),
    (
        "stripe_key", "critical",
        r"(?i)(stripe[_-]?secret|stripe[_-]?api[_-]?key)\s*[=:]\s*",
        r"['\"]?sk_(?:live|test)_[A-Za-z0-9]{24,}['\"]?",
    ),
    (
        "database_url", "high",
        r"(?i)(database[_-]?url|db[_-]?url|connection[_-]?string)\s*[=:]\s*",
        r"['\"]?(postgres|mysql|mongodb|redis|sqlite)[^'\"]{0,200}['\"]?",
    ),
    (
        "private_key", "critical",
        r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----",
        r"",  # the pattern itself is enough
    ),
    (
        "github_token", "critical",
        r"(?i)(github[_-]?token|ghp_|gho_|ghs_)",
        r"[A-Za-z0-9_]{20,}",
    ),
    (
        "slack_token", "high",
        r"(?i)(slack[_-]?token|xox[bpaso]-)",
        r"[A-Za-z0-9\-]{20,}",
    ),
]

# Files that commonly contain secrets and should be in .gitignore
SENSITIVE_FILE_PATTERNS = [
    ".env", ".env.local", ".env.production", ".env.staging", ".env.development",
    "*.pem", "*.key", "*.p12", "*.pfx", "credentials.json", "serviceAccount.json",
    "config/secrets.yml", "config/secrets.yaml",
]

# Required .gitignore patterns for a secure Python project
REQUIRED_GITIGNORE_PATTERNS = [
    ".env",
    "*.pem",
    "*.key",
    "venv/",
    "__pycache__/",
    "*.pyc",
    "*.db",
    ".DS_Store",
    "*.log",
    "node_modules/",
]


# ------------------------------------------------------------------ #
# Scanner                                                              #
# ------------------------------------------------------------------ #

class SecretScanner:
    """Scans files and directories for leaked secrets and env misconfigurations."""

    SKIP_DIRS = {".git", "__pycache__", "venv", "env", ".venv", "node_modules"}
    SCAN_EXTENSIONS = {".py", ".env", ".yml", ".yaml", ".json", ".toml", ".cfg", ".ini", ".conf", ".txt"}

    def scan_file(self, filepath: str, relative_to: str = "") -> list[SecretFinding]:
        """Scan a single file for secrets."""
        path = Path(filepath)
        if not path.exists():
            return []

        display_path = str(path.relative_to(relative_to)) if relative_to else str(path)
        findings: list[SecretFinding] = []

        try:
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return []

        for line_no, line in enumerate(lines, 1):
            stripped = line.strip()
            # Skip comments
            if stripped.startswith("#") or stripped.startswith("//"):
                continue

            for secret_type, severity, key_pat, val_pat in SECRET_PATTERNS:
                full_pattern = key_pat + (val_pat if val_pat else "")
                match = re.search(full_pattern, line, re.IGNORECASE)
                if match:
                    # Extract only the variable name, not the value
                    key_match = re.search(key_pat, line, re.IGNORECASE)
                    variable = key_match.group(0).strip().rstrip("=: ").strip("\"'") if key_match else secret_type
                    findings.append(SecretFinding(
                        severity=severity,
                        type=secret_type,
                        file=display_path,
                        line=line_no,
                        variable=variable,
                        description=f"Potential {secret_type.replace('_', ' ')} detected in '{display_path}' at line {line_no}.",
                        remediation=(
                            f"Move '{variable}' to a .env file and load via os.getenv(). "
                            "Ensure .env is listed in .gitignore. "
                            "Rotate the secret immediately if it was ever committed."
                        ),
                    ))
                    break  # one finding per line per file

        return findings

    def scan_directory(self, root_path: str) -> SecretScanResult:
        """Full directory secret scan + gitignore audit."""
        root = Path(root_path)
        result = SecretScanResult()

        # Gitignore check
        result.gitignore_report = self.audit_gitignore(root_path)

        # Find .env files
        for env_file in root.rglob(".env*"):
            if any(part in self.SKIP_DIRS for part in env_file.parts):
                continue
            rel = str(env_file.relative_to(root))
            result.env_files_found.append(rel)
            # Check if it would be committed (not in gitignore)
            if not self._is_gitignored(root_path, rel):
                result.exposed_env_files.append(rel)

        # Scan all relevant files
        for path in sorted(root.rglob("*")):
            if any(part in self.SKIP_DIRS for part in path.parts):
                continue
            if path.is_file() and path.suffix in self.SCAN_EXTENSIONS:
                findings = self.scan_file(str(path), relative_to=root_path)
                result.findings.extend(findings)
                result.scanned_files += 1

        logger.info(
            "Secret scan: %d files, %d findings, %d env files",
            result.scanned_files, len(result.findings), len(result.env_files_found),
        )
        return result

    def audit_gitignore(self, root_path: str) -> GitignoreReport:
        """Check .gitignore for required security patterns."""
        report = GitignoreReport()
        gitignore_path = Path(root_path) / ".gitignore"

        if not gitignore_path.exists():
            report.found = False
            report.missing_patterns = REQUIRED_GITIGNORE_PATTERNS[:]
            return report

        report.found = True
        content = gitignore_path.read_text()
        existing_lines = [l.strip() for l in content.splitlines() if l.strip() and not l.startswith("#")]

        for pattern in REQUIRED_GITIGNORE_PATTERNS:
            # Loose match — .env covers .env.local etc.
            base = pattern.rstrip("/").lstrip("*.")
            if any(base in line for line in existing_lines):
                report.present_patterns.append(pattern)
            else:
                report.missing_patterns.append(pattern)

        report.is_sufficient = len(report.missing_patterns) == 0
        return report

    @staticmethod
    def _is_gitignored(root_path: str, relative_file: str) -> bool:
        """Quick heuristic: check if a pattern in .gitignore covers the file."""
        gitignore = Path(root_path) / ".gitignore"
        if not gitignore.exists():
            return False
        for line in gitignore.read_text().splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            # Simple prefix/suffix match
            base = line.rstrip("/").lstrip("*.")
            if base and base in relative_file:
                return True
        return False
