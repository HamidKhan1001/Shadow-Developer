"""
Tests for the Code Monitor and Secret Scanner modules.
"""
import textwrap
from pathlib import Path
import pytest

from src.monitor.code_scanner import CodeScanner
from src.monitor.secret_scanner import SecretScanner, GitignoreReport


# ------------------------------------------------------------------ #
# CodeScanner — snippet tests                                          #
# ------------------------------------------------------------------ #

class TestCodeScanner:
    def setup_method(self):
        self.scanner = CodeScanner()

    def test_detects_sql_injection(self):
        code = 'cursor.execute(f"SELECT * FROM users WHERE id={user_id}")'
        result = self.scanner.scan_code_snippet(code)
        ids = [f.rule_id for f in result.findings]
        assert "INJ-001" in ids or "INJ-002" in ids

    def test_detects_shell_injection(self):
        code = "subprocess.run(cmd, shell=True)"
        result = self.scanner.scan_code_snippet(code)
        assert any(f.rule_id == "INJ-003" for f in result.findings)

    def test_detects_eval(self):
        code = "result = eval(user_input)"
        result = self.scanner.scan_code_snippet(code)
        assert any(f.rule_id == "INJ-004" for f in result.findings)

    def test_detects_disabled_ssl(self):
        code = "requests.get(url, verify=False)"
        result = self.scanner.scan_code_snippet(code)
        assert any(f.rule_id == "AUTH-001" for f in result.findings)

    def test_detects_md5(self):
        code = "hashlib.md5(data.encode()).hexdigest()"
        result = self.scanner.scan_code_snippet(code)
        assert any(f.rule_id == "CRYPTO-001" for f in result.findings)

    def test_detects_sha1(self):
        code = "h = hashlib.sha1(token.encode())"
        result = self.scanner.scan_code_snippet(code)
        assert any(f.rule_id == "CRYPTO-002" for f in result.findings)

    def test_detects_hardcoded_password(self):
        code = "password = 'supersecret123'"
        result = self.scanner.scan_code_snippet(code)
        assert any(f.rule_id == "SEC-001" for f in result.findings)

    def test_detects_hardcoded_api_key(self):
        code = "api_key = 'sk-abcdef1234567890abcdef'"
        result = self.scanner.scan_code_snippet(code)
        assert any(f.rule_id == "SEC-002" for f in result.findings)

    def test_detects_debug_mode(self):
        code = "DEBUG = True"
        result = self.scanner.scan_code_snippet(code)
        assert any(f.rule_id == "CFG-001" for f in result.findings)

    def test_detects_pickle(self):
        code = "obj = pickle.loads(data)"
        result = self.scanner.scan_code_snippet(code)
        assert any(f.rule_id == "DESER-001" for f in result.findings)

    def test_detects_unsafe_yaml(self):
        code = "data = yaml.load(stream)"
        result = self.scanner.scan_code_snippet(code)
        assert any(f.rule_id == "DESER-002" for f in result.findings)

    def test_clean_code_no_findings(self):
        code = textwrap.dedent("""
            import os
            import hashlib
            import secrets
            password = os.getenv('DB_PASSWORD')
            api_key = os.getenv('API_KEY')
            token = secrets.token_hex(32)
            h = hashlib.sha256(token.encode()).hexdigest()
        """)
        result = self.scanner.scan_code_snippet(code)
        assert len(result.findings) == 0

    def test_finding_has_correct_fields(self):
        code = "cursor.execute(f\"SELECT * FROM t WHERE id={uid}\")"
        result = self.scanner.scan_code_snippet(code)
        assert len(result.findings) > 0
        f = result.findings[0]
        assert f.line == 1
        assert f.severity in ("critical", "high", "medium", "low", "info")
        assert f.rule_id
        assert f.snippet
        assert f.description
        assert f.remediation

    def test_summary_counts_severities(self):
        code = textwrap.dedent("""
            password = 'abc123'
            DEBUG = True
            cursor.execute(f"SELECT * FROM t WHERE id={x}")
        """)
        result = self.scanner.scan_code_snippet(code)
        assert result.summary.get("critical", 0) + result.summary.get("high", 0) > 0

    def test_scan_directory(self, tmp_path: Path):
        (tmp_path / "bad.py").write_text("password = 'hunter2'\ncursor.execute(f\"SELECT {x}\")\n")
        (tmp_path / "good.py").write_text("import os\npw = os.getenv('DB_PASSWORD')\n")
        result = self.scanner.scan_directory(str(tmp_path))
        assert result.scanned_files == 2
        assert len(result.findings) >= 1


# ------------------------------------------------------------------ #
# SecretScanner                                                        #
# ------------------------------------------------------------------ #

class TestSecretScanner:
    def setup_method(self):
        self.scanner = SecretScanner()

    def test_detects_hardcoded_password_in_env(self, tmp_path: Path):
        (tmp_path / ".env").write_text("DB_PASSWORD=supersecret\nAPI_KEY=sk-abc123456789012345\n")
        findings = self.scanner.scan_file(str(tmp_path / ".env"))
        assert len(findings) >= 1

    def test_detects_aws_key(self, tmp_path: Path):
        (tmp_path / "config.py").write_text("AWS_ACCESS_KEY_ID = 'AKIAIOSFODNN7EXAMPLE'\n")
        findings = self.scanner.scan_file(str(tmp_path / "config.py"))
        assert any(f.type == "aws_key" for f in findings)

    def test_clean_env_file_no_findings(self, tmp_path: Path):
        (tmp_path / "config.py").write_text(
            "import os\nAPI_KEY = os.getenv('API_KEY')\nDB_URL = os.getenv('DATABASE_URL')\n"
        )
        findings = self.scanner.scan_file(str(tmp_path / "config.py"))
        assert len(findings) == 0

    def test_variable_name_not_value_in_finding(self, tmp_path: Path):
        (tmp_path / "s.py").write_text("api_key = 'sk-reallysecretvalue12345'\n")
        findings = self.scanner.scan_file(str(tmp_path / "s.py"))
        assert len(findings) > 0
        # The actual secret value should NOT be in the finding
        for f in findings:
            assert "reallysecretvalue12345" not in f.variable
            assert "reallysecretvalue12345" not in f.description

    def test_gitignore_audit_missing_patterns(self, tmp_path: Path):
        (tmp_path / ".gitignore").write_text("*.pyc\n__pycache__/\n")
        report = self.scanner.audit_gitignore(str(tmp_path))
        assert report.found is True
        assert ".env" in report.missing_patterns
        assert report.is_sufficient is False

    def test_gitignore_audit_sufficient(self, tmp_path: Path):
        patterns = "\n".join([
            ".env", "*.pem", "*.key", "venv/", "__pycache__/", "*.pyc",
            "*.db", ".DS_Store", "*.log", "node_modules/",
        ])
        (tmp_path / ".gitignore").write_text(patterns)
        report = self.scanner.audit_gitignore(str(tmp_path))
        assert report.found is True
        assert report.is_sufficient is True

    def test_gitignore_not_found(self, tmp_path: Path):
        report = self.scanner.audit_gitignore(str(tmp_path))
        assert report.found is False
        assert len(report.missing_patterns) > 0


# ------------------------------------------------------------------ #
# API endpoints for monitor                                            #
# ------------------------------------------------------------------ #

class TestMonitorAPI:
    def test_scan_code_snippet(self, client):
        resp = client.post("/api/v1/scan/code", json={
            "code": "password = 'hunter2'\ncursor.execute(f\"SELECT * FROM t WHERE id={x}\")",
            "filename": "test.py"
        })
        assert resp.status_code == 200
        body = resp.json()
        assert body["total_findings"] >= 1
        assert "findings" in body
        assert body["findings"][0]["severity"] in ("critical", "high", "medium", "low")

    def test_scan_code_clean(self, client):
        resp = client.post("/api/v1/scan/code", json={
            "code": "import os\napi_key = os.getenv('API_KEY')\n",
            "filename": "clean.py"
        })
        assert resp.status_code == 200
        assert resp.json()["total_findings"] == 0

    def test_scan_code_missing_params(self, client):
        resp = client.post("/api/v1/scan/code", json={})
        assert resp.status_code == 400

    def test_scan_secrets_on_project(self, client):
        resp = client.post("/api/v1/scan/secrets", json={"path": "."})
        assert resp.status_code == 200
        body = resp.json()
        assert "gitignore_report" in body
        assert "findings" in body
        assert body["gitignore_report"]["found"] is True

    def test_scan_gitignore_endpoint(self, client):
        resp = client.get("/api/v1/scan/gitignore?path=.")
        assert resp.status_code == 200
        body = resp.json()
        assert "gitignore_found" in body
        assert "missing_patterns" in body

    def test_scan_demo_endpoint(self, client):
        resp = client.post("/api/v1/scan/demo")
        assert resp.status_code == 200
        body = resp.json()
        assert len(body["demo_scans"]) == 3
        # First two should have findings, last one should be clean
        assert body["demo_scans"][0]["total_findings"] > 0
        assert body["demo_scans"][1]["total_findings"] > 0
        assert body["demo_scans"][2]["total_findings"] == 0
