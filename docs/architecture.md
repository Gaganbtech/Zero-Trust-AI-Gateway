# Zero-Trust Runtime Security Gateway - Architecture & Threat Model

## 1. System Architecture Overview

The Zero-Trust Runtime Security Gateway is designed on the foundational premise: **"Never trust an AI agent's decision; authenticate the workload, authorize every protected action, validate its arguments, execute only approved operations, inspect resulting data, and record an immutable security event."**

Prompt-injection defense is treated as a defense-in-depth layer rather than the sole perimeter boundary.

```mermaid
flowchart TD
    subgraph Client_Zone["Untrusted Client & AI Workload Zone"]
        Operator["Security Analyst / Admin\n(Next.js SOC Dashboard)"]
        Agent["Autonomous Cloud AI Agent\n(Workload Identity Bearer)"]
        MCPClient["MCP Clients\n(Claude Desktop / Cursor)"]
    end

    subgraph Gateway_Boundary["Zero-Trust Security Gateway Boundary"]
        subgraph Ingress_Layer["1. Authentication & Ingress"]
            WorkloadVerifier["Workload Identity Verifier\n(Cryptographic JWT / Scope Binding)"]
            HumanSession["Human Auth & RBAC\n(Session JWT / HttpOnly Cookie)"]
            RateLimit["Rate Limiter & Correlation ID Middleware"]
        end

        subgraph Security_Mediation["2. Runtime Security Mediation Engine"]
            InputScanner["Prompt & Injection Scanner\n(Heuristics, Delimiter Guard, Canaries)"]
            ToolRegistry["Central Tool Registry\n(Strict Schemas & Risk Ratings)"]
            OPAEvaluator["Policy Client\n(OPA Rego v1 / Fail-Closed)"]
            ExecutionGuard["Controlled Tool Executor\n(Least-Privilege Isolation)"]
            SSRFGuard["Outbound Egress Guard\n(Anti-DNS Rebinding / IP Filters)"]
            DLPProcessor["Recursive DLP Engine\n(Luhn Check / Secret Masking)"]
        end

        subgraph Specialized_Engines["3. Extension Gateways & Posture Engines"]
            LLMProxy["LLM Streaming Proxy\n(Gemini / OpenAI / Claude / Sim)"]
            MCPGateway["MCP Gateway Server\n(JSON-RPC 2.0 Endpoint)"]
            AttackStudio["Interactive Attack Studio\n(12-Step Execution Tracing)"]
            CSPMPlatform["AI-CSPM Platform Engine\n(NIST AI RMF, CIS K8s, OWASP)"]
        end

        subgraph Persistence_Audit["4. Cryptographic Audit & Telemetry"]
            TamperChain["Tamper-Evident Audit Chain\n(HMAC-SHA256 Hash Chaining)"]
            IncidentDetector["Incident Correlation Engine\n(Automated Remediation Alerts)"]
            Telemetry["Prometheus Metrics & Tracing\n(/metrics, SSE Event Feed)"]
        end
    end

    subgraph Policy_Tier["Policy Management Engine"]
        OPA["Open Policy Agent (OPA)\n(Rego v1 Rules)"]
    end

    subgraph Data_Tier["Protected Data & External Services"]
        PostgresDB[("PostgreSQL / SQLite Database\n- App, Audit & Posture Records\n- Tenant-Scoped Customer Data")]
        ApprovedAPIs["Approved External APIs\n(HTTPS Egress Allowlist)"]
        LLMProviders["Upstream LLM Providers\n(Google, Anthropic, OpenAI)"]
    end

    Operator -->|Session Token| HumanSession
    Agent -->|Workload JWT| WorkloadVerifier
    MCPClient -->|JSON-RPC Request| MCPGateway
    
    WorkloadVerifier --> RateLimit
    HumanSession --> RateLimit
    
    RateLimit --> InputScanner
    InputScanner --> ToolRegistry
    ToolRegistry --> OPAEvaluator
    OPAEvaluator <-->|Policy Decision Query| OPA
    
    ToolRegistry -->|Parameterized DB Call| ExecutionGuard
    ExecutionGuard -->|Tenant-Scoped SQL| PostgresDB
    
    ToolRegistry -->|HTTP Egress Call| SSRFGuard
    SSRFGuard -->|Pin Resolved IP| ApprovedAPIs

    MCPGateway --> ToolRegistry
    LLMProxy --> InputScanner
    LLMProxy -->|Proxy Outbound Stream| LLMProviders
    LLMProxy --> ToolRegistry
    AttackStudio --> InputScanner
    CSPMPlatform --> PostgresDB
    
    ExecutionGuard --> DLPProcessor
    SSRFGuard --> DLPProcessor
    LLMProxy --> DLPProcessor
    
    DLPProcessor --> TamperChain
    TamperChain --> PostgresDB
    TamperChain --> IncidentDetector
    IncidentDetector --> PostgresDB
    TamperChain --> Telemetry
```

---

## 2. Trust Boundaries and Threat Model

### Trust Boundaries (TB)
1. **TB-1: Agent Workload Boundary**: The AI model / agent code is completely untrusted. Even if compromised by prompt injection, it has no direct network access or database credentials.
2. **TB-2: Gateway Ingress Boundary**: All requests must present a signed, non-expired workload identity token. Workload identity is bound to a specific `tenant_id` and permitted tool scopes.
3. **TB-3: Policy Enforcement Point (PEP)**: The gateway queries OPA before dispatching any tool. Production mode fails closed.
4. **TB-4: Execution & Data Boundary**: Operations on data use predefined parameterized queries. Model-generated arbitrary SQL is never executed.
5. **TB-5: Egress Network Boundary**: Outbound HTTP requests must be pre-resolved, checked against forbidden private/loopback/cloud-metadata networks, and bound to approved hostnames.
6. **TB-6: Egress DLP Boundary**: Data returned by tools is recursively inspected and redacted for PII and secrets prior to reaching the agent or operator.
7. **TB-7: Audit Storage Boundary**: Audit events are persisted in a tamper-evident SHA-256 HMAC hash chain, preventing undetected tampering or retroactive deletion.
8. **TB-8: LLM Proxy Boundary**: Intercepts prompts, injects canary tokens, performs pre-flight DLP, evaluates autonomous tool calls via OPA, and sanitizes output streams.
9. **TB-9: Model Context Protocol (MCP) Boundary**: Standard JSON-RPC 2.0 tool calls from developer environments (Claude Desktop, Cursor) are evaluated against policy and sanitized before execution.
10. **TB-10: Multi-Cloud CSPM Boundary**: Evaluates cloud environments across NIST AI RMF, CIS Kubernetes, OWASP LLM, and MITRE ATLAS with isolated read-only audit connectors.

### STRIDE Threat Analysis

| Threat Category | Potential Attack Vector | Gateway Mitigation Control |
| :--- | :--- | :--- |
| **Spoofing** | Attacker calls gateway claiming another `agent_id` in request body. | Gateway rejects request body `agent_id` and binds execution exclusively to cryptographically verified JWT subject (`workload.agent_id`). |
| **Tampering** | Rogue actor modifies audit logs to conceal unauthorized access. | Cryptographic HMAC-SHA256 hash chaining. `verify_audit_log_integrity` pinpoints any record modification or gap. |
| **Repudiation** | Operator denies reviewing or altering security incidents. | Role-Based Access Control (RBAC) logs user identities on notes and status changes. |
| **Information Disclosure** | AI agent attempts to exfiltrate credit cards, SSNs, or AWS keys. | Recursive DLP engine inspects strings, arrays, and objects, applying Luhn validation and regex masking before return. |
| **Denial of Service** | Model sends 10MB payload or requests 10,000 database rows. | Strict row limits (max 20 rows), input length caps (4000 chars), and HTTP response size bounding (512KB). |
| **Elevation of Privilege** | Prompt injection commands agent to execute `DROP TABLE customers`. | Tool registry enforces `allowed_operations=["SELECT"]`. Parameterized query templates never execute DDL/DML. |
| **SSRF** | Agent tricked into hitting `http://169.254.169.254/latest/meta-data`. | Controlled HTTP client resolves DNS, rejects link-local / RFC 1918 / loopback IPs, and verifies domain allowlist. |
| **Tool Abuse via MCP** | Compromised developer agent executes dangerous SQL or outbound scans via MCP. | MCP Gateway runs every tool call through OPA policy evaluation, SSRF validation, and DLP sanitization. |
| **LLM Output Poisoning** | Adversarial model output attempts to trick downstream workflows into exfiltrating secrets. | LLM Streaming Proxy verifies canary tokens, redacts PII/credentials dynamically, and tracks per-stream latency. |
| **Cloud AI Misconfiguration** | Unencrypted vector DBs, public model endpoints, or unpinned K8s security contexts. | AI-CSPM Platform scans cloud infrastructure continuously against NIST AI RMF and CIS benchmarks, providing copyable CLI remediation scripts. |
