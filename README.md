# Shadow Developer

**The Autonomous Spec-Driven Audit Agent**

Shadow Developer intercepts AI-generated feature prompts and audits them for security vulnerabilities, API drift, and architectural conflicts — before a single line of production code is written. It ships as a FastAPI backend with a built-in web IDE, real-time code scanner, and a multi-agent audit pipeline wired to Kiro and AWS.

---

## The Problem

AI coding agents move fast. Too fast. A developer types *"add a Stripe webhook route"* and within seconds an agent has scaffolded a handler — with no HMAC signature verification, a raw SQL query, and a hardcoded API key sitting in plain text. The code compiles. The tests pass. The PR ships. The breach happens three weeks later.

The bottleneck in AI-accelerated development is not speed — it is **context drift**. Agents generate code against a snapshot of your intent, not a full understanding of your codebase's security posture, API contracts, or existing schema.

Shadow Developer solves this by auditing the *specification* before code generation begins.

---

## How It Works

```
Developer Prompt
      |
      v
[Shadow Interceptor]  ←  FastAPI gateway, captures every prompt
      |
   +--+--+
   |     |
[Kiro   [Shadow Auditor]  ←  adversarial spec generation
 Agent]       |               OWASP rules, API drift, schema checks
   |          |
   +----+-----+
        |   Spec Alignment Check
        v
[Orchestration Validator]
   · Conflict scoring         · API drift detection
   · OWASP rule evaluation    · Auto test generation
        |
        v
  FAILED → block   /   NEEDS REVISION → rewrite   /   PASSED → proceed
```

### The 4-Step Pipeline

**Step 1 — Intercept**
The developer's natural language prompt is captured by the Shadow Interceptor before any code generation begins. The system pulls the project's global architectural context from the vector store.

**Step 2 — Parallel Spec Generation**
Two agents run concurrently. The Kiro Feature Agent drafts the implementation specification. The Shadow Audit Agent generates an adversarial specification — an explicit list of everything the proposed feature could break.

**Step 3 — Adversarial Auditing**
The Shadow Auditor applies 20+ security and architectural rules against the prompt and the scanned codebase. It checks for SQL injection patterns, hardcoded credentials, missing webhook signature verification, API route collisions, schema migration conflicts, and dependency version mismatches.

**Step 4 — Reconciliation and Verdict**
The Orchestration Validator diffs both specs. Critical issues halt code generation entirely. High-severity findings require revision. Clean prompts proceed with auto-generated integration and regression tests attached.

---

## Features

### Spec Audit Engine
- Natural language prompt interception via `POST /api/v1/intercept`
- OWASP A01–A10 aligned rule set applied to every prompt
- API drift detection against registered routes and HTTP methods
- Schema collision detection against existing Pydantic and SQLAlchemy models
- Dependency version conflict checking against pinned requirements
- Auto-generated test suggestions for every conflict found
- Full audit history persisted to local SQLite database

### Real-Time Code Scanner
- Static analysis of Python source files as you type
- 20 rules across 6 categories: injection, auth, crypto, secrets, config, deserialization
- Rule IDs with exact file, line number, and column for every finding
- Severity classification: CRITICAL, HIGH, MEDIUM, LOW
- AST-level checks: `except: pass` swallowing errors, `assert` used for auth

### Secret Scanner
- Detects hardcoded API keys, passwords, tokens, AWS credentials, private keys
- Scans `.env`, `.yml`, `.json`, `.toml`, `.cfg` files
- Captures variable names only — secret values are never logged or returned
- `.gitignore` audit: checks for 9 required security patterns

### Web IDE
- VS Code-style dark editor at `/ide`
- Syntax highlighting, line gutter with severity markers, minimap
- Four auto-type demo scenarios with real security findings
- Integrated Security panel, Spec Audit panel, and History tab
- Step-by-step presenter notes strip at the bottom

### Kiro Agent Layer
- `shadow_auditor.json` — Claude 3 Sonnet agent for adversarial spec generation
- `validator.json` — Claude 3 Sonnet agent (temperature 0) for spec reconciliation
- `audit_pipeline.yaml` — declarative 6-step agent execution graph

---

## Tech Stack

| Layer | Technology |
|---|---|
| AI Engine | Kiro (spec generation, agent orchestration) |
| Backend | FastAPI + Uvicorn (async Python) |
| Database | SQLite via SQLAlchemy 2.0 async + aiosqlite |
| Vector Store | In-memory (demo) / Amazon OpenSearch Serverless (production) |
| Embeddings | Amazon Bedrock Titan Embed (production) |
| LLM | Amazon Bedrock — Anthropic Claude 3 Sonnet |
| Code Analysis | Python AST + regex rule engine |
| Tests | pytest + pytest-asyncio (72 tests) |

---

## Project Structure

```
shadow-developer/
├── src/
│   ├── interceptor/
│   │   ├── main.py          # FastAPI app, lifespan, CORS, routing
│   │   ├── router.py        # All API routes including /intercept, /history, /seed, /scan/*
│   │   ├── ide.py           # Serves the web IDE and landing page
│   │   └── models.py        # Pydantic models: AuditResult, ConflictDetail, AuditStatus
│   ├── auditor/
│   │   ├── engine.py        # AuditEngine: 4-step pipeline, scoring, test suggestions
│   │   └── rules/
│   │       ├── security.py  # 5 OWASP rules (SQL injection, auth bypass, secrets, webhooks, rate limiting)
│   │       └── architecture.py  # 3 drift rules (API, schema, dependency)
│   ├── context/
│   │   ├── parser.py        # AST-based codebase scanner, CLI entry point
│   │   └── vector_store.py  # InMemoryVectorStore (demo) + AWS OpenSearch (production)
│   ├── monitor/
│   │   ├── code_scanner.py  # 20-rule static security scanner, AST + regex
│   │   └── secret_scanner.py  # Secret detection, .gitignore audit
│   ├── static/
│   │   ├── ide.html         # Full web IDE (SVG icons, syntax highlight, minimap)
│   │   └── landing.html     # Product landing page
│   ├── database.py          # SQLite schema, async CRUD: AuditRecord
│   ├── config.py            # Pydantic Settings, env-based config
│   └── requirements.txt
├── .kiro/
│   ├── agents/
│   │   ├── shadow_auditor.json   # Adversarial audit agent definition
│   │   └── validator.json        # Spec reconciliation agent definition
│   └── workflows/
│       └── audit_pipeline.yaml   # 6-step agent execution graph
├── tests/
│   ├── test_audit_engine.py   # 20 unit tests for security + architecture rules
│   ├── test_interceptor.py    # 12 HTTP integration tests
│   ├── test_context_parser.py # 8 AST parser tests
│   ├── test_monitor.py        # 28 code scanner + secret scanner tests
│   └── test_vector_store.py   # 5 vector store tests
├── data/
│   └── demo_prompts.json     # 7 labeled demo scenarios
├── scripts/
│   └── run_demo.py           # Terminal demo runner with Rich output
├── .env.example
├── .gitignore
├── Makefile
└── pytest.ini
```

---

## Quick Start

**Requirements:** Python 3.11, no AWS account needed for local demo

```bash
# Clone
git clone https://github.com/HamidKhan1001/Shadow-Developer.git
cd Shadow-Developer

# Install (use Python 3.11 — 3.13 has Rust build issues with pydantic-core)
python3.11 -m venv venv
source venv/bin/activate
pip install -r src/requirements.txt

# Start
uvicorn src.interceptor.main:app --host 0.0.0.0 --port 8000 --reload
```

Open `http://localhost:8000`

```bash
# Seed demo data into the database
curl -X POST http://localhost:8000/api/v1/seed

# Run all tests
pytest tests/ -v

# Terminal demo (server must be running)
python scripts/run_demo.py
```

### Environment Variables (optional, for AWS features)

Copy `.env.example` to `.env`:

```env
AWS_REGION=us-east-1
BEDROCK_MODEL_ID=anthropic.claude-3-sonnet-20240229-v1:0
OPENSEARCH_ENDPOINT=https://your-cluster.us-east-1.aoss.amazonaws.com
OPENSEARCH_INDEX=shadow-dev-context
KIRO_API_KEY=your_kiro_agent_key
```

Without these set, the system runs fully in local demo mode — no AWS required.

---

## API Reference

| Method | Route | Description |
|---|---|---|
| `GET` | `/` | Landing page |
| `GET` | `/ide` | Web IDE |
| `GET` | `/docs` | Swagger UI |
| `POST` | `/api/v1/intercept` | Audit a feature prompt |
| `GET` | `/api/v1/audit/{id}` | Retrieve an audit result |
| `GET` | `/api/v1/history` | List recent audits |
| `POST` | `/api/v1/seed` | Load all 7 demo prompts |
| `POST` | `/api/v1/scan/code` | Scan a code snippet or file |
| `POST` | `/api/v1/scan/secrets` | Scan a directory for leaked secrets |
| `GET` | `/api/v1/scan/gitignore` | Audit .gitignore completeness |
| `POST` | `/api/v1/scan/demo` | Run pre-built demo scans |
| `GET` | `/api/v1/health` | Health check |

### Example: Intercept a prompt

```bash
curl -X POST http://localhost:8000/api/v1/intercept \
  -H "Content-Type: application/json" \
  -d '{
    "prompt": "Add a Stripe webhook route that processes payment events",
    "project_id": "ecommerce-platform-v2",
    "author": "hamid.khan",
    "branch": "feature/webhooks"
  }'
```

Response:
```json
{
  "audit_id": "4c2e5df9-d3e2-4c44-b5bb-76585146aba9",
  "status": "needs_revision",
  "message": "Audit requires revision — 1 high-severity issue found.",
  "conflicts": [
    {
      "severity": "high",
      "category": "security",
      "description": "Webhook route detected but no mention of signature verification.",
      "affected_component": "webhook handler",
      "remediation": "Always validate payloads using HMAC-SHA256 against a shared secret."
    }
  ],
  "recommended_tests": [
    "Integration test: verify endpoint returns 401 for unauthenticated requests",
    "Security test: validate that webhook handler rejects malformed payloads"
  ]
}
```

### Example: Scan a code snippet

```bash
curl -X POST http://localhost:8000/api/v1/scan/code \
  -H "Content-Type: application/json" \
  -d '{
    "code": "cursor.execute(f\"SELECT * FROM users WHERE id={user_id}\")",
    "filename": "search.py"
  }'
```

---

## Detection Coverage

### Security Rules (prompt + code scanning)

| Rule ID | Severity | Category | What it catches |
|---|---|---|---|
| INJ-001 | CRITICAL | Injection | cursor.execute with f-string interpolation |
| INJ-002 | CRITICAL | Injection | f-string SQL passed to execute() |
| INJ-003 | HIGH | Injection | subprocess with shell=True |
| INJ-004 | HIGH | Injection | eval() and \_\_import\_\_() calls |
| INJ-005 | HIGH | Injection | os.system() calls |
| AUTH-001 | CRITICAL | Auth | SSL verify=False |
| AUTH-002 | HIGH | Auth | JWT decoded with algorithm 'none' |
| AUTH-003 | HIGH | Auth | Comments indicating skipped auth checks |
| AUTH-004 | MEDIUM | Auth | CORS allow_origins=* |
| CRYPTO-001 | CRITICAL | Crypto | hashlib.md5 usage |
| CRYPTO-002 | HIGH | Crypto | hashlib.sha1 usage |
| CRYPTO-003 | HIGH | Crypto | random.random() in security context |
| SEC-001 | CRITICAL | Secrets | Hardcoded password strings |
| SEC-002 | CRITICAL | Secrets | Hardcoded API keys |
| SEC-003 | HIGH | Secrets | Hardcoded auth tokens |
| SEC-004 | HIGH | Secrets | Private keys in source files |
| CFG-001 | HIGH | Config | DEBUG=True |
| CFG-002 | MEDIUM | Config | Weak SECRET_KEY |
| CFG-003 | MEDIUM | Config | Server bound to 0.0.0.0 |
| DESER-001 | CRITICAL | Injection | pickle.loads on untrusted data |
| DESER-002 | HIGH | Injection | yaml.load without Loader |

### Architectural Rules (prompt auditing)

| Rule | Severity | What it catches |
|---|---|---|
| API Drift | HIGH | Proposed path conflicts with existing registered route + method |
| Schema Collision | MEDIUM | Model referenced in prompt already exists in codebase |
| Dependency Conflict | MEDIUM | Requested library version mismatches pinned version |

---

## Running Tests

```bash
# Full suite
pytest tests/ -v

# With coverage
pytest tests/ -v --cov=src --cov-report=term-missing

# Single module
pytest tests/test_monitor.py -v
```

**72 tests, all passing** across 5 test files.

---

## Demo Scenarios

Seven pre-built scenarios in `data/demo_prompts.json`, loadable via `POST /api/v1/seed`:

| # | Scenario | Expected Result |
|---|---|---|
| 1 | Clean endpoint with rate limiting | PASSED |
| 2 | Webhook without signature verification | NEEDS REVISION (HIGH) |
| 3 | Webhook with HMAC verification | PASSED |
| 4 | Raw SQL via cursor.execute | FAILED (CRITICAL) |
| 5 | Admin endpoint bypassing auth | FAILED (CRITICAL) |
| 6 | Modifying existing User model | PASSED with warnings |
| 7 | Dependency version upgrade conflict | PASSED with warnings |

---

## Video Script

> Use this as your talking track for the demo video. Each section maps to a screen you should have open. The step notes in the IDE bottom strip follow this same order.

---

### Opening (0:00 – 0:20)

Open `http://localhost:8000` — the landing page.

*"AI coding agents are fast. But fast and insecure is worse than slow. Shadow Developer is a security layer that sits between the developer's intent and the code that gets written. It audits the specification before a single line is generated."*

---

### The Problem (0:20 – 0:45)

Stay on the landing page. Point to the code preview block.

*"Here's a real example. A developer asks an AI agent to add a Stripe webhook. The agent writes the code. It compiles. But look — a hardcoded API key, a raw SQL query that's wide open to injection, and MD5 being used as a security hash. None of this was caught. Shadow Developer catches all three before generation even starts."*

---

### Opening the IDE (0:45 – 1:00)

Click "Open IDE" — navigate to `http://localhost:8000/ide`.

*"This is the Shadow Developer IDE. It looks like a standard code editor, but it has a live security scanner running behind every file."*

Point to the file tree on the left.

*"These badges tell you the health of each file at a glance. webhook.py has 4 issues. charge.py is clean."*

---

### Live Code Scan (1:00 – 1:30)

Click `webhook.py` in the sidebar — the file loads and scans automatically.

*"When you open a file, Shadow Developer scans it immediately. The right panel shows the findings. Four issues — two critical, one high, one high. Each one has an exact line number, a rule ID, and a fix."*

Hover over a finding card to show the tooltip.

*"The gutter markers turn red on dangerous lines. You see exactly where the threat is."*

---

### Demo Scenario 1 — SQL Injection (1:30 – 2:00)

Click "SQL Injection" in the bottom notes strip.

*"Now I'll show you something more powerful — real-time detection. Watch the right panel as the code types."*

Let the auto-type run. When the finding appears mid-type:

*"There it is. The scanner caught cursor.execute with an f-string on line 8 before the file was even finished being written. Rule INJ-001, severity CRITICAL."*

---

### Demo Scenario 2 — Auth Bypass (2:00 – 2:30)

Click "Auth Bypass".

*"This scenario shows what happens when a developer takes a shortcut. DEBUG=True. A TODO comment that says skip auth for now. And os.system with shell=True — that's a command injection waiting to happen. Shadow Developer flags all three."*

Point to the severity badges in the right panel.

*"Critical in red. High in orange. Every finding has a concrete fix, not just a warning."*

---

### Demo Scenario 3 — Hardcoded Keys (2:30 – 3:00)

Click "Hardcoded Keys".

*"This is one of the most common causes of production breaches — credentials committed to source code. Stripe API key, AWS access key, database password, all sitting in plain text. Shadow Developer catches every one of them. And critically — it never logs or returns the actual secret value. Only the variable name."*

---

### Spec Audit Panel (3:00 – 3:40)

After the Hardcoded Keys demo finishes, the IDE auto-switches to the Spec Audit tab.

*"The Spec Audit is a different layer. Instead of scanning written code, it audits a feature description before any code is generated at all. This is the core of Shadow Developer — it's why it's spec-driven."*

The audit result appears. Point to the conflicts.

*"The audit engine checked this prompt against the project's registered API routes, existing data models, and OWASP rules. It found a missing webhook signature check and flagged it as high severity before a single line was written."*

---

### Safe Code (3:40 – 4:00)

Click "Safe Code".

*"For balance — here's what a clean file looks like. Environment variables for credentials, SHA-256 instead of MD5, parameterized queries, proper subprocess calls. Zero findings. Shadow Developer doesn't flag things that are actually safe."*

---

### History Tab (4:00 – 4:15)

Click the History tab in the right panel.

*"Every audit is persisted to a local SQLite database. You can see the full history — which prompts were flagged, which passed, which author, which branch."*

---

### Closing (4:15 – 4:30)

Navigate back to `http://localhost:8000`.

*"Shadow Developer is a meta-layer for AI-driven development. It doesn't replace the agent — it makes the agent accountable. Built on Kiro's spec-driven workflow, backed by AWS Bedrock and OpenSearch in production, and running fully locally with zero config for development. Security before the code. That's the only way to ship fast without shipping broken."*

---

### Recording Tips

- Record at 1920x1080, crop the bottom 40px to hide the presenter notes strip
- Use a browser with no extensions visible in the toolbar
- Move your mouse deliberately between elements — give each finding card a moment on screen
- The auto-type speed is intentionally readable — do not fast-forward the demo sections
- Seed the database first (`curl -X POST http://localhost:8000/api/v1/seed`) so the History tab is populated before you record

---

## Why This Wins

**It is meta-Kiro.** Rather than building another application on top of Kiro, Shadow Developer builds a developer tool *for* the Kiro ecosystem. The entire pipeline depends on spec-driven development — the adversarial spec, the alignment check, the auto-generated tests. This is Kiro's core workflow turned inward.

**It is genuinely useful.** The code scanner, secret scanner, and prompt auditor solve real problems that exist right now in AI-assisted development. Every finding in the demo is a real vulnerability that ships to production regularly.

**It bridges Kiro and AWS cleanly.** The vector store plugs into Amazon OpenSearch Serverless. Embeddings come from Bedrock Titan. The LLM agents run on Claude 3 Sonnet. The local demo works without any of this — but the production path is a single environment variable change.

**It is complete.** Landing page, IDE, API, tests, demo data, agent configs, workflow definitions. Not a concept — a working system.

---

## License

MIT
