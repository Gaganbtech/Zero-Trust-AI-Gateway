# Zero-Trust Runtime Security Gateway - Operations Runbook

## 1. Quick Start Guide for macOS

### Prerequisites
- macOS 12+ (Apple Silicon or Intel)
- Python 3.12+ (Installed via Homebrew: `brew install python@3.12`)
- Node.js 20+ (Installed via Homebrew: `brew install node`)
- Open Policy Agent (Installed via Homebrew: `brew install opa`)
- Docker Desktop (Optional, for full containerized stack)

### Local Development Setup Commands
```bash
# 1. Create and activate Python 3.12 virtual environment
python3.12 -m venv .venv
source .venv/bin/activate

# 2. Upgrade pip and install dependencies
pip install --upgrade pip
pip install -r requirements.txt

# 3. Configure local environment variables
cp .env.example .env

# 4. Run database migrations and seed synthetic records
alembic upgrade head
python -c "from app.database import init_database; init_database()"

# 5. Start OPA Policy Engine in background
opa run --server --addr=127.0.0.1:8181 policies/agent.rego &

# 6. Start FastAPI Backend Gateway
uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload &

# 7. Start Next.js Frontend Security Dashboard
cd frontend
npm install
npm run dev
```

The services will be available at:
- **Security Dashboard**: [http://127.0.0.1:3000](http://127.0.0.1:3000)
- **API Documentation (Swagger UI)**: [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)
- **Prometheus Metrics**: [http://127.0.0.1:8000/metrics](http://127.0.0.1:8000/metrics)
- **OPA Health**: [http://127.0.0.1:8181/health](http://127.0.0.1:8181/health)

---

## 2. Docker Compose Deployment

To start the full production-like containerized stack (PostgreSQL, OPA, FastAPI backend, Next.js dashboard):

```bash
# Build and start all services
docker compose up -d --build

# Inspect running containers
docker compose ps

# View unified logs
docker compose logs -f

# Verify database health
docker compose exec postgres pg_isready -U gateway_user

# Run Alembic migrations inside container
docker compose exec backend alembic upgrade head

# Graceful shutdown
docker compose down
```

---

## 3. Database Migration & Maintenance

### Running Migrations
```bash
# Apply all pending migrations to head
PYTHONPATH=. alembic upgrade head

# Generate a new migration revision after modifying models
PYTHONPATH=. alembic revision --autogenerate -m "describe_change"

# Roll back the most recent migration
PYTHONPATH=. alembic downgrade -1
```

### Backup and Restore
```bash
# PostgreSQL Backup
pg_dump -U gateway_user -h localhost -d zero_trust_gateway -F c -b -v -f backup_$(date +%Y%m%d_%H%M%S).dump

# PostgreSQL Restore
pg_restore -U gateway_user -h localhost -d zero_trust_gateway -v backup_file.dump
```

---

## 4. Operational Playbooks: Specialized Engines

### A. AI-CSPM Multi-Cloud Posture Operations
- **Trigger a Posture Scan**:
  ```bash
  curl -s -X POST http://127.0.0.1:8000/api/v1/cspm-platform/scans \
    -H "Content-Type: application/json" \
    -d '{"environment_id": "<env_uuid>", "scan_type": "FULL_AUDIT"}'
  ```
- **Fetch Compliance Framework Breakdown**:
  ```bash
  curl -s http://127.0.0.1:8000/api/v1/cspm-platform/frameworks/nist-ai-rmf
  ```
- **Remediating Findings**: Each finding in `GET /api/v1/cspm-platform/findings` includes an executable CLI remediation block (e.g. AWS CLI, `kubectl`, or Terraform) ready for copy-paste or automated execution.

### B. Zero-Trust LLM Proxy Operations
- **Supported Providers**: Google Gemini, Anthropic Claude, OpenAI, and Deterministic Simulator.
- **Configuring Keys**: Set `GEMINI_API_KEY`, `ANTHROPIC_API_KEY`, or `OPENAI_API_KEY` in `.env`.
- **Pre-Flight Ingress**: Automatically redacts credentials/PII and plants canary tokens before dispatching to upstream LLMs.
- **Tool Interception**: When an LLM requests tool execution (`db_query`, `safe_http`), the gateway intercepts the call, validates it against OPA, executes safely, and masks results before the model resumes streaming.

### C. Model Context Protocol (MCP) Integration
- **Endpoint**: `POST /api/v1/mcp` (Standard JSON-RPC 2.0).
- **Configure Claude Desktop (`claude_desktop_config.json`)**:
  ```json
  {
    "mcpServers": {
      "zero-trust-gateway": {
        "url": "http://127.0.0.1:8000/api/v1/mcp"
      }
    }
  }
  ```
- **Guarantees**: Even if an external agent prompts Claude or Cursor to execute destructive operations or exfiltrate data, all tool calls route through OPA default-deny authorization, SSRF IP validation, and recursive DLP sanitization.

### D. Interactive Attack Studio Operations
- **Available Vectors**: Prompt Injection, DAN Jailbreak, Workload Identity Spoofing, SSRF Cloud Metadata Theft, Destructive SQL, C2 Exfiltration, Cross-Tenant Breach, DLP Secret Leak.
- **Run Scenario**:
  ```bash
  curl -s -X POST http://127.0.0.1:8000/api/v1/simulator/run \
    -H "Content-Type: application/json" \
    -d '{"scenario_id": "attack-ssrf-metadata"}'
  ```
- **Evaluation**: Returns a 12-step trace detailing which step blocked the attack, execution latency per step in microseconds, and STRIDE remediation advice.

---

## 5. Automated Testing Procedures

Execute all test suites using the following commands:

```bash
# 1. Run all 108 unit, integration, and security tests
./.venv/bin/pytest -v

# 2. Run OPA policy unit tests
opa test policies/ -v

# 3. Run frontend TypeScript & Next.js production build verification
cd frontend && npm run build && cd ..

# 4. Run automated end-to-end security verification script
./scripts/demo.sh
```

---

## 6. Security Incident Response Runbooks

### Runbook 1: Destructive Operation Attempt (`DESTRUCTIVE_OPERATION_ATTEMPT`)
- **Detection**: An agent requested `DROP`, `DELETE`, `UPDATE`, `ALTER`, or `TRUNCATE`.
- **Automated Mitigation**: Gateway blocks action immediately with HTTP 403 (`destructive_sql_prohibited`).
- **Analyst Action**:
  1. Inspect the agent session timeline in the dashboard to locate the triggering user prompt.
  2. Verify if the agent model experienced prompt injection or tool hallucination.
  3. If persistent, suspend the agent identity via `UPDATE agents SET status='SUSPENDED' WHERE id='<agent_id>'`.

### Runbook 2: Potential Data Exfiltration (`DATA_EXFILTRATION_SUSPECTED`)
- **Detection**: Input scanner flagged prompt seeking bulk credentials or sensitive records.
- **Automated Mitigation**: Gateway rejects prompt with HTTP 400 (`PROMPT_INJECTION_SUSPECTED`).
- **Analyst Action**:
  1. Review retrieved documents or external content ingested by the agent for indirect prompt injection.
  2. Confirm DLP rules masked any unintended sensitive fields.

### Runbook 3: SSRF / Egress Violation (`SSRF_EGRESS_VIOLATION`)
- **Detection**: Outbound HTTP requested private IP, cloud metadata, or unapproved domain.
- **Automated Mitigation**: Network client denies socket connection with HTTP 403 (`ssrf_*`).
- **Analyst Action**:
  1. Determine if the requested URL is an approved partner API; if valid, submit a pull request updating `ALLOWED_OUTBOUND_DOMAINS` and `policies/agent.rego`.
  2. If the URL targeted `169.254.169.254` or internal RFC 1918 addresses, treat as an active adversary probe.

---

## 7. Production Readiness Checklist

| Category | Requirement | Implementation Status |
| :--- | :--- | :--- |
| **Authentication** | Cryptographic Workload Identity JWTs (Audience, Issuer, Expiry) | Confirmed (`app/auth/security.py`) |
| **Authentication** | Human Operator Session & Server-Side RBAC (`admin`, `analyst`, `auditor`, `viewer`) | Confirmed (`app/auth/rbac.py`) |
| **Authorization** | OPA Policy Engine with default-deny | Confirmed (`policies/agent.rego`) |
| **Authorization** | Production fail-closed enforcement (`OPA_FAIL_CLOSED=1`) | Confirmed (`app/core/config.py`) |
| **Database** | Parameterized query templates (No arbitrary model SQL) | Confirmed (`app/tools/db_tool.py`) |
| **Database** | Multi-tenant isolation at data access layer | Confirmed (`Customer.tenant_id == workload.tenant_id`) |
| **Network** | SSRF prevention (Loopback, RFC 1918, Cloud Metadata 169.254.169.254) | Confirmed (`app/network/ssrf.py`) |
| **Network** | Anti-DNS rebinding and redirect revalidation | Confirmed (`app/network/client.py`) |
| **DLP** | Recursive JSON/List inspection for PII and API keys | Confirmed (`app/dlp/engine.py`) |
| **DLP** | Luhn algorithm credit card validation | Confirmed (`luhn_checksum_valid`) |
| **Audit** | Cryptographic HMAC-SHA256 tamper-evident hash chain | Confirmed (`app/audit/tamper.py`) |
| **Audit** | Real-time SSE streaming of security events | Confirmed (`app/api/v1/dashboard.py`) |
| **LLM Mediation** | Multi-provider streaming proxy with canary checks & pre-flight DLP | Confirmed (`app/llm/proxy.py`) |
| **MCP Protocol** | Standard JSON-RPC 2.0 tool server with zero-trust mediation | Confirmed (`app/mcp/server.py`) |
| **Attack Studio**| 8 attack vector scenarios with microsecond 12-step tracing | Confirmed (`app/scenarios/engine.py`) |
| **CSPM Platform**| Multi-cloud audit across NIST AI RMF, CIS K8s, OWASP, MITRE ATLAS | Confirmed (`app/cspm/platform_service.py`) |
| **Frontend** | Next.js 16 App Router SOC console with 10 dedicated security tabs | Confirmed (`frontend/`) |
| **Testing** | Automated tests across all security domains (108 pytest + 9 OPA) | Confirmed (100% passing) |
