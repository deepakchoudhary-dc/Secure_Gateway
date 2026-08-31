# AI Security Gateway — Secure.AI Hub

A FastAPI-based **AI Security Gateway** that proxies LLM calls through layered inspection: input sanitization, semantic jailbreak detection, RAG injection checks, credential/PII redaction, system-prompt leakage guard, sandboxed code execution, and human-in-the-loop (HITL) review. All decisions are traced, logged, and auditable.

> **Status:** Functional prototype with production hardening in progress. See *Limitations* below. Local SQLite is fine for `clone → run`; production requires Postgres + Redis + Vault (see *Production*).

---

## What it actually does

- **Input pipeline:** length checks → topic-lock rails → anomaly scan → regex blocklist (40+ patterns, leetspeak + base64 decode) → TF-IDF semantic jailbreak similarity (with learned feedback) → RAG indirect-injection scan → **DLP gate** (credential formats block outright, bulk PII + corporate/financial prose blocked by threshold).
- **Classification:** HuggingFace `martin-ha/toxic-comment-model` when available, heuristic fallback otherwise. Scores feed policy decisions.
- **Policy & HITL:** DB-driven policies (regex, thresholds, rate limits, RBAC). Flagged requests go to a **priority queue** (critical/high/medium/low by risk score), support **batch approve/deny**, **SLA escalation**, and **SSE live updates** (`GET /hitl/events`). Decisions are optionally **webhooked** and auto-resumed via a durable outbox.
- **LLM routing:** Primary → fallback with circuit breakers, retry with backoff budgets, and **egress allowlist + public-IP DNS checks** (no redirects). Provider sessions are pooled. Responses are **hash-cached** (tenant-scoped) and **streamable** via `POST /process/stream` with a hold-back PII buffer and kill-switch.
- **Output:** system-prompt leakage guard (phrase + overlap), PII/token redaction (credit cards, emails, phones, API keys, JWTs, DB URLs, etc.).
- **Audit:** Structured JSON logs, Prometheus metrics, incident export (time-bounded, tenant-scoped, redacted), and token accounting per tenant.

---

## Architecture

```
[ Client ] → [ Topic-lock & Input Filters ] → [ AI Classifier ] → [ Policy / HITL ] → [ Sandbox ] → [ LLM Provider (primary → fallback) ] → [ Leakage Guard & PII Redactor ] → Response
                                                            ↓
                                              [ Outbox (notifications/webhooks) + Feedback learning loop ]
```

---

## Quick start (local, no deps beyond pip)

```bash
git clone https://github.com/deepakchoudhary-dc/Something-is-coming-up-next.git
cd Something-is-coming-up-next
python -m venv .venv
# Windows: .venv\Scripts\activate  |  Unix: source .venv/bin/activate
pip install -r requirements.txt
python run.py  # http://localhost:8000  (dashboard at /)
# tests:
pytest -q
```

Local defaults: `DATABASE_URL=sqlite:///./ai_security.db`, `REQUIRE_AUTH=false` in test, no Redis/Vault required. Hit the playground at `/` to exercise the pipeline.

Optional: the HuggingFace toxicity classifier needs `pip install -r requirements-ai.txt` (heavy, ~2 GB for torch); without it the gateway uses the heuristic classifier automatically. For production-parity testing without Docker, point `DATABASE_URL` at a local Postgres and `REDIS_URL` at a local Redis and run `alembic upgrade head` first.

---

## Production deployment

**Do not use `run.py` or SQLite in production.** Use the production compose (Postgres + Redis) and set required env vars:

```bash
# 1. Create .env for production
APP_ENV=production
SECRET_KEY=<64+ random chars, ≥32>
API_KEY=<32+ random chars>
ADMIN_API_KEY=<32+ random chars, different>
AUTH_MODE=jwt
JWT_SECRET_KEY=<64+ random chars, HS256 ≥32 or RS256 keypair>
DATABASE_URL=postgresql://gateway:${POSTGRES_PASSWORD}@db:5432/ai_security
REDIS_URL=redis://:${REDIS_PASSWORD}@redis:6379/0
REDIS_PASSWORD=<32+ random chars, Redis auth — required by compose>
DATA_ENCRYPTION_KEY=<32+ random chars, dedicated field-encryption key (v2)>
VAULT_ADDR=https://vault.yourcompany.com
VAULT_TOKEN=<vault-token>
SECRETS_BACKEND=vault
PROVIDER_EGRESS_ALLOWLIST=api.openai.com,api.anthropic.com
WEBHOOK_EGRESS_ALLOWLIST=hooks.yourcompany.com
ALLOWED_ORIGINS=https://yourdomain.com
DATA_RETENTION_DAYS=90
ENCRYPT_LOGS_AT_REST=true
HITL_EMAIL=security-team@yourcompany.com
# optional: REDIS_URL, WEBHOOK_URL, SMTP_*

# 2. Build & run
docker compose up --build
# or: gunicorn -w 4 -k uvicorn.workers.UvicornWorker src.main:app

# 3. Migrations (first start only, or on upgrade)
alembic upgrade head
```

**Required prod env vars (enforced at boot, app will crash if missing):**
`SECRET_KEY` (≥32, not placeholder), `API_KEY`/`ADMIN_API_KEY` (≥32, different) or `JWT_*` pair, `DATABASE_URL` (non-sqlite), `PROVIDER_EGRESS_ALLOWLIST`, `WEBHOOK_EGRESS_ALLOWLIST`, `REDIS_URL` (redis://), `SECRETS_BACKEND=vault`, `VAULT_ADDR` (https), `HITL_EMAIL` (not `admin@example.com`), `ENCRYPT_LOGS_AT_REST=true`, `DATA_RETENTION_DAYS>0`, `REDIS_URL`, plus `ALLOWED_ORIGINS` (https, no wildcard). `SANDBOX_EXECUTION_ENABLED` requires `SANDBOX_RUNNER_COMMAND` or `false`.

**Encryption key model (field-level, at rest):** ciphertext is versioned. Set `DATA_ENCRYPTION_KEY` (≥32) for the dedicated v2 key, independent of `SECRET_KEY` so signing secrets can rotate without touching stored data. Rows encrypted before `DATA_ENCRYPTION_KEY` existed (`enc:v1:`, derived from `SECRET_KEY`) remain readable, so enabling v2 is non-destructive. Decryption failures raise loudly — they are never masked with a placeholder.

---

## API surface

| Method | Path | Auth | Purpose |
|---|---|---|---|
| POST | `/api/v1/process` | user | Main gateway (idempotency via `Idempotency-Key`) |
| POST | `/api/v1/process/stream` | user | Streaming SSE variant, same guards, hold-back PII scan |
| GET | `/api/v1/config` | admin | Get provider/topic config (keys masked) |
| POST | `/api/v1/config` | admin | Update provider/topic config |
| GET | `/api/v1/policies` | admin | List policies |
| POST | `/api/v1/policies` | admin | Update policies |
| GET | `/api/v1/hitl/pending` | admin | Priority queue, tenant-scoped, SLA auto-escalated |
| GET | `/api/v1/hitl/events` | admin | SSE live updates for HITL queue |
| POST | `/api/v1/hitl/approve/{id}` | admin | Approve/deny one |
| POST | `/api/v1/hitl/batch` | admin | Batch approve/deny |
| POST | `/api/v1/hitl/escalate` | admin | Force SLA escalation check |
| GET | `/api/v1/hitl/status/{id}` | admin | Single request details |
| POST | `/api/v1/hitl/assign/{id}` | admin | Assign reviewer |
| GET | `/api/v1/hitl/history` | admin | Tenant-scoped history |
| GET | `/api/v1/monitoring/logs` | admin | Tenant-scoped logs |
| GET | `/api/v1/monitoring/stats` | admin | Tenant-scoped aggregates |
| GET | `/api/v1/monitoring/metrics` | admin | JSON or Prometheus (`?format=prometheus`) |
| GET | `/api/v1/monitoring/alerts` | admin | Threshold alerts |
| POST | `/api/v1/monitoring/incidents/export` | admin | Time-bounded export, tenant-filtered |
| GET | `/api/v1/monitoring/circuit-breakers` | admin | CB states |
| GET | `/api/v1/redteaming/payloads` | admin | Payload registry (when `REDTEAM_ENDPOINTS_ENABLED`) |
| POST | `/api/v1/redteaming/scan` | admin | Run scanner (feeds learning loop) |
| POST | `/api/v1/auth/token` | admin | Issue JWT |
| POST | `/api/v1/auth/revoke` | admin | Revoke presented JWT (jti denylist) |
| DELETE | `/api/v1/admin/tenants/{tenant_id}/data` | admin | Erase tenant data (retention/GDPR) |
| GET | `/health` | — | Liveness |
| GET | `/ready` | — | Readiness (DB + migrations) |

---

## Project structure

```
src/
  gateway/       # router, idempotency, response_cache
  filters/       # InputFilter (regex, DLP, corporate gate, topic lock)
  classifiers/   # AI classifier, semantic detector, feedback_model
  policy/        # PolicyManager (single source DEFAULT_POLICY_RULES)
  hitl/          # HITL manager (priority, batch, SLA, resume)
  monitoring/    # database models, logger, metrics, incident_export
  providers/     # base, openai, anthropic, gemini, mock, circuit_breaker, retry, router_provider
  queue/         # outbox (notifications + webhooks), notifications
  auth/          # jwt_auth (jti revocation), rbac, tenant
  secrets/       # secrets_manager, field_crypto (Fernet)
  sandbox/       # sandbox_manager, sandbox_wrapper
  config/        # settings (production gates)
  static/        # dashboard SPA
migrations/versions/  # Alembic (001..007)
deploy/          # backup.sh / restore.sh
```

---

## Limitations (honest)

- **Detection is heuristic** (regex + TF-IDF + small toxicity model). Sophisticated paraphrase, multilingual, and Unicode tricks can bypass; embeddings + NER are the upgrade path (interface is pluggable).
- **Multi-turn attacks** are not tracked — each request is stateless.
- **SQLite** is fine locally but serializes writes; use Postgres for any real load (see compose).
- **In-process rate limiting** is per-worker; Redis is used in production when `REDIS_URL` is set (fail-closed), otherwise in-process.
- **Encryption at rest** is field-level Fernet with versioned keys: `enc:v1:` derived from `SECRET_KEY` (legacy), `enc:v2:` from the dedicated `DATA_ENCRYPTION_KEY`. Setting `DATA_ENCRYPTION_KEY` is non-destructive — legacy rows stay readable. Rotation still requires a re-encryption pass (same semantics as `006_encrypt_sensitive_data.py`); no Vault transit auto-rotation yet.
- **History in git** still shows the pre-rotation API keys in commit `ef2876c` for ~90 days (GitHub GC). Rotate any reused credentials.

---

## Contributing

1. Fork, branch, add tests
2. `pytest -q` must be 104/104 (currently deterministic, mocked provider)
3. PR

## License

MIT — see `LICENSE`.

## Security

This is a *gateway* — prompts are still sent to the configured LLM provider and are subject to that provider's data policy. For sensitive data, use a self-hosted OpenAI-compatible endpoint (`custom` provider pointing at Ollama/vLLM) so prompts never leave your network.
