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

> Your full talking track. Spoken lines are in quotes — say them naturally, don't read them word for word. Direction notes tell you what to have on screen. Total runtime: ~4.5 minutes.
>
> **Before you hit record:** run `curl -X POST http://localhost:8000/api/v1/seed` to populate the history tab, open the browser to `http://localhost:8000`, hide extensions, set resolution to 1920x1080.

---

### The Hook — Start here, no screen yet (0:00 – 0:30)

*No screen. Just you talking to camera or voiceover on a black frame.*

> "I want to tell you about a Tuesday afternoon that probably cost a company about forty thousand dollars.
>
> A developer on their team was using an AI coding agent. Moving fast — Kiro, Copilot, whatever. They typed: 'add a Stripe webhook that updates subscription status.' The agent wrote the code in seconds. It looked fine. It passed the linter. The PR got merged.
>
> Three weeks later, someone noticed the webhook had no signature verification. Any request from anyone could update any user's subscription. The hardcoded Stripe key in the file had already been rotated by then — but not before it hit the logs.
>
> The code was never wrong. The *intent* was wrong. And nobody caught it because the review happened after the code existed, not before.
>
> That's what Shadow Developer fixes."

---

### Introduce the Idea (0:30 – 1:00)

*Open `http://localhost:8000` — the landing page.*

> "The idea is straightforward. Right now, AI agents generate code and then we audit it. Shadow Developer flips that. It audits the *specification* — the feature description — before any code is written at all.
>
> Think of it as a shadow agent that runs alongside your main coding agent. Every time you describe a feature, Shadow Developer reads it, checks it against your codebase's security rules, your existing API contracts, your database schema — and if something's wrong, it blocks generation before the mistake exists."

*Point to the headline on the landing page.*

> "Catch security flaws before the code exists. That's the whole idea."

*Scroll down slowly to the code preview block.*

> "And this — this is a real example of what it catches. A webhook.py file with three critical issues highlighted. Hardcoded API key, SQL injection via an f-string query, MD5 hash used for security. All flagged. All with rule IDs and fixes. We'll see this live in a second."

---

### The IDE — First Look (1:00 – 1:20)

*Click "Open IDE" — `http://localhost:8000/ide` loads.*

> "This is the Shadow Developer IDE. It runs in the browser, looks like a standard code editor, but it has a live security scanner behind every file.
>
> Look at the sidebar. Each file has a badge — webhook.py shows four issues, charge.py is clean. The moment you open a file, it scans automatically. No buttons to press."

*Click `webhook.py` — findings load in the right panel.*

> "Four findings. Two critical, two high. Right panel breaks them down — rule ID, line number, what the problem is, and exactly how to fix it. The gutter turns red on the dangerous lines. You don't have to hunt for it."

*Hover over a finding card slowly.*

> "Hover over any card and you get the full detail. This is real static analysis — not suggestions, not style warnings. Actual security vulnerabilities."

---

### Demo 1 — SQL Injection, Real Time (1:20 – 1:55)

*Click "SQL Injection" in the bottom notes bar.*

> "Now here's what makes this interesting. Watch the right panel while the code types."

*Let the auto-type run. Don't talk over it — let the finding appear mid-type.*

*When the CRITICAL badge appears in the right panel:*

> "There. The scanner caught it on line 8 — cursor.execute with an f-string interpolating user input directly into a SQL query. Rule INJ-001. CRITICAL severity. It didn't wait for the file to finish. It flagged it as it was being written.
>
> That's the behaviour you want. Not a PR comment three days later. Not a SAST scan before deploy. Right here, right now, before the code is committed."

---

### Demo 2 — Auth Bypass (1:55 – 2:25)

*Click "Auth Bypass".*

> "This one is about developer shortcuts. We've all done it — 'I'll fix the auth later, just need to get this working.' Except later never comes.
>
> Watch — DEBUG=True gets flagged immediately. Then a comment that literally says 'skip auth check for now.' And os.system with a user-controlled string — that's remote code execution waiting to happen.
>
> Three separate issues. Three different rule categories. All caught in the same file."

*Let the scan complete and point to the right panel.*

> "Critical in red. High in orange. And every single one comes with a specific remediation — not 'fix your auth.' It tells you exactly what to use instead."

---

### Demo 3 — Hardcoded Credentials (2:25 – 2:55)

*Click "Hardcoded Keys".*

> "This is the one that keeps security engineers up at night. Credentials in source code. It's been a known problem for decades and it still happens every single day, because it's just so easy to do when you're moving fast.
>
> Stripe key. AWS access key. AWS secret. Database password. All hardcoded, all sitting in plain text, all one `git push` away from being public."

*When findings appear:*

> "Five findings. And notice — Shadow Developer reports the variable name, never the value. It doesn't echo your secrets back at you. That's intentional."

---

### The Spec Audit — Before Code Exists (2:55 – 3:35)

*The IDE auto-switches to the Spec Audit tab after the demo completes.*

> "The code scanner is powerful, but it only works on code that already exists. The Spec Audit works *before* code exists — and that's the real innovation here.
>
> This is what just ran. The audit engine took that feature description — 'add a SendGrid notification with the API key configured in code' — and checked it against the project's registered routes, existing data models, and OWASP rules.
>
> It came back with a high-severity conflict before a single line was written. Missing webhook signature verification. Missing rate limiting. If this prompt had gone straight to the agent, we'd have another webhook.py situation."

*Point to the recommended tests section.*

> "And it doesn't just block. It generates the tests you need to pass before this feature gets merged. Integration test, security test, regression test — all named, all specific."

---

### Demo 4 — Safe Code (3:35 – 3:50)

*Click "Safe Code".*

> "I want to show you the other side too. This is what clean code looks like through Shadow Developer's eyes.
>
> Environment variables. SHA-256. Parameterized ORM queries. Cryptographically random tokens. Subprocess with a list, not a shell string."

*Wait for the scan to complete — zero findings.*

> "Zero findings. Status bar goes green. Shadow Developer is not a false-positive machine. If the code is actually safe, it says so."

---

### History — The Audit Trail (3:50 – 4:05)

*Click the History tab in the right panel.*

> "Every single audit is stored. Who ran it, which branch, which project, what the prompt was, how many conflicts were found.
>
> In a team setting, this is your audit trail. You can see exactly when a risky prompt was caught, who submitted it, and whether it was revised or blocked. That's accountability built into the workflow."

---

### The Close (4:05 – 4:30)

*Navigate back to `http://localhost:8000`. Hold on the landing page.*

> "We're at a really interesting point in software development right now. AI agents can write code faster than any human. But speed without judgment just means you get to production failure faster.
>
> Shadow Developer is a judgment layer. It sits between the developer's intent and the code that gets generated. It uses Kiro's spec-driven approach — the same approach that makes Kiro different — but turns it inward, to audit the spec itself before it becomes code.
>
> AWS Bedrock for the LLM agents. OpenSearch for the architectural context store. FastAPI for the interceptor. And Kiro as the orchestration layer that makes all of it work together.
>
> The breach on that Tuesday afternoon? Shadow Developer would have caught it on Monday morning, before the PR existed.
>
> That's the project."

---

### Recording Tips

- Do not read the script verbatim — use it as a guide, speak in your own voice
- Pause for 1–2 seconds after each demo finding appears before speaking — let the viewer register what they're seeing
- The auto-type demos run at a readable pace — resist the urge to skip ahead
- Crop the bottom 40px of the recording to hide the presenter notes strip
- Keep mouse movements slow and intentional — hover over findings, don't just click past them
- The History tab needs demo data — run `curl -X POST http://localhost:8000/api/v1/seed` before recording
- Total target length: 4 to 4.5 minutes. Under 5 is perfect for a hackathon submission

---

## Why This Wins

**It is meta-Kiro.** Rather than building another application on top of Kiro, Shadow Developer builds a developer tool *for* the Kiro ecosystem. The entire pipeline depends on spec-driven development — the adversarial spec, the alignment check, the auto-generated tests. This is Kiro's core workflow turned inward.

**It is genuinely useful.** The code scanner, secret scanner, and prompt auditor solve real problems that exist right now in AI-assisted development. Every finding in the demo is a real vulnerability that ships to production regularly.

**It bridges Kiro and AWS cleanly.** The vector store plugs into Amazon OpenSearch Serverless. Embeddings come from Bedrock Titan. The LLM agents run on Claude 3 Sonnet. The local demo works without any of this — but the production path is a single environment variable change.

**It is complete.** Landing page, IDE, API, tests, demo data, agent configs, workflow definitions. Not a concept — a working system.

---

## License

MIT
