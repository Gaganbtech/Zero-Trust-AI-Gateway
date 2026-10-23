import re
import os
import secrets
from contextlib import asynccontextmanager
from pathlib import Path
from fastapi import FastAPI, HTTPException, Query, Header, Request, Depends, status, Response
from fastapi.responses import HTMLResponse, PlainTextResponse
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session

from app.core.config import settings
from app.database.session import get_db
from app.database.init_db import init_database
from app.database.models import AuditEvent
from app.auth.workload import VerifiedWorkload
from app.gateway.engine import mediate_tool_action
from app.scanners.prompt import scan_prompt
from app.dlp.engine import redact_text_content, inspect_and_sanitize_payload, DLPAction
from app.audit.service import record_security_event, query_audit_events, get_dashboard_statistics
from app.observability.metrics import get_metrics_payload
from app.observability.middleware import ObservabilityMiddleware
from app.schemas.gateway import AgentPromptRequest, ActionRequest, DLPRequest

# Routers
from app.api.v1.health import router as health_router
from app.api.v1.auth import router as auth_router
from app.api.v1.agents import router as agents_router
from app.api.v1.security import router as security_router
from app.api.v1.audit import router as audit_router
from app.api.v1.incidents import router as incidents_router
from app.api.v1.policies import router as policies_router
from app.api.v1.dashboard import router as dashboard_router
from app.api.v1.cspm import router as cspm_router


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Validate production configuration at startup
    settings.validate_production_readiness()
    # Initialize and seed database
    init_database()
    yield


app = FastAPI(
    title=settings.APP_NAME,
    version=settings.VERSION,
    description="Zero-Trust Runtime Security Gateway for Cloud-Based AI Agents",
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc"
)

# 1. Observability and correlation middleware
app.add_middleware(ObservabilityMiddleware)

# 2. Private Network Access (PNA) and CORS middleware
@app.middleware("http")
async def pna_cors_middleware(request: Request, call_next):
    # Handle Chrome Private Network Access preflights
    if request.method == "OPTIONS" and request.headers.get("access-control-request-private-network") == "true":
        origin = request.headers.get("origin", "*")
        resp = Response(content="OK", status_code=200)
        resp.headers["Access-Control-Allow-Origin"] = origin
        resp.headers["Access-Control-Allow-Credentials"] = "true"
        resp.headers["Access-Control-Allow-Private-Network"] = "true"
        resp.headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, DELETE, OPTIONS, PATCH"
        resp.headers["Access-Control-Allow-Headers"] = request.headers.get("access-control-request-headers", "*")
        return resp
    response = await call_next(request)
    if "origin" in request.headers:
        response.headers["Access-Control-Allow-Private-Network"] = "true"
    return response

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_origin_regex=r"^https?://(localhost|127\.0\.0\.1|0\.0\.0\.0|192\.168\.\d+\.\d+)(:\d+)?$",
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# 3. Include API v1 Routers
app.include_router(health_router)
app.include_router(auth_router)
app.include_router(agents_router)
app.include_router(security_router)
app.include_router(audit_router)
app.include_router(incidents_router)
app.include_router(policies_router)
app.include_router(dashboard_router)
app.include_router(cspm_router)



# 4. Observability Metrics Endpoint
@app.get("/metrics", summary="Prometheus Metrics", tags=["Observability"])
async def metrics():
    content, content_type = get_metrics_payload()
    return Response(content=content, media_type=content_type)


# =====================================================================
# BACKWARD COMPATIBILITY LAYER
# Preserves compatibility with existing tests and scripts
# =====================================================================

@app.get("/health", tags=["Legacy Compatibility"])
async def legacy_health():
    return {
        "status": "ok",
        "policy_mode": "OPA" if settings.OPA_FAIL_CLOSED else "OPA with local fallback",
        "opa_url": settings.OPA_URL,
        "version": settings.VERSION
    }


@app.get("/dashboard", response_class=HTMLResponse, tags=["Legacy Compatibility"])
async def legacy_dashboard():
    dashboard_file = Path(__file__).parent / "dashboard.html"
    if dashboard_file.exists():
        return dashboard_file.read_text(encoding="utf-8")
    return "<h1>Zero-Trust Gateway Dashboard API Online</h1>"


@app.post("/agent/run", tags=["Legacy Compatibility"])
async def legacy_run_agent(
    request: AgentPromptRequest,
    req: Request,
    db: Session = Depends(get_db)
):
    correlation_id = getattr(req.state, "correlation_id", None)
    flagged_res = scan_prompt(request.prompt)
    if flagged_res.is_flagged:
        event = record_security_event(
            agent_id="demo-agent",
            tenant_id="tenant-alpha",
            tool="prompt_scan",
            operation="PROMPT",
            decision="BLOCK",
            reason=flagged_res.reason,
            destination="agent://input",
            correlation_id=correlation_id,
            prompt_flagged=True,
            metadata={"prompt_length": len(request.prompt), "category": flagged_res.category},
            db=db
        )
        raise HTTPException(
            status_code=400,
            detail={
                "error": "Prompt blocked by input security policy",
                "event_id": event["event_id"],
                "reason": flagged_res.reason
            }
        )

    # Intent resolution
    prompt_lower = request.prompt.lower()
    if "weather" in prompt_lower or "temperature" in prompt_lower:
        action_dict = {
            "agent_id": "demo-agent",
            "tool": "weather",
            "operation": "GET",
            "destination": "https://api.weather.example/v1/current",
            "method": "GET",
            "args": {"city": "Bengaluru"}
        }
    else:
        action_dict = {
            "agent_id": "demo-agent",
            "tool": "db_query",
            "operation": "SELECT",
            "table": "customers",
            "destination": "sqlite://demo",
            "method": "INTERNAL",
            "args": {"columns": ["id", "name", "email"], "limit": 10}
        }

    workload = VerifiedWorkload(
        agent_id="demo-agent",
        tenant_id="tenant-alpha",
        scopes=["customer:read", "weather:read", "http:egress"],
        allowed_tools=["db_query", "weather", "safe_http"],
        issuer="zero-trust-gateway-demo-agent"
    )

    result = await mediate_tool_action(action_dict, workload, db, correlation_id)
    return {
        "agent_id": "demo-agent",
        "answer": result["result"],
        "security": {
            "decision": result["decision"],
            "event_id": result["event_id"],
            "correlation_id": result["correlation_id"]
        }
    }


@app.post("/actions", tags=["Legacy Compatibility"])
async def legacy_mediate_action(
    action: ActionRequest,
    req: Request,
    authorization: str | None = Header(default=None),
    db: Session = Depends(get_db)
):
    correlation_id = getattr(req.state, "correlation_id", None)
    expected = "Bearer " + settings.GATEWAY_AGENT_TOKEN
    if not authorization or not secrets.compare_digest(authorization, expected):
        raise HTTPException(status_code=401, detail="Agent authentication required")

    sql = (action.sql or "").strip()
    if action.tool == "db_query" and sql:
        if not re.match(r"(?is)^SELECT\b", sql) or re.search(r"(?is)\b(DROP|DELETE|UPDATE|INSERT|ALTER|TRUNCATE|ATTACH|DETACH|PRAGMA)\b", sql) or ";" in sql.rstrip(";"):
            event = record_security_event(
                agent_id=action.agent_id,
                tenant_id="tenant-alpha",
                tool=action.tool,
                operation=action.operation,
                decision="BLOCK",
                reason="unsafe_sql_shape",
                destination=action.destination,
                correlation_id=correlation_id,
                risk_level="HIGH",
                metadata={"sql_present": True},
                db=db
            )
            raise HTTPException(
                status_code=403,
                detail={"error": "Action blocked", "event_id": event["event_id"], "reason": "unsafe_sql_shape"}
            )

    # In legacy route, dev token authenticates workload identity 'demo-agent'
    workload = VerifiedWorkload(
        agent_id="demo-agent",
        tenant_id="tenant-alpha",
        scopes=["customer:read", "weather:read", "http:egress"],
        allowed_tools=["db_query", "weather", "safe_http"],
        issuer="zero-trust-gateway-legacy-compat"
    )

    action_dict = action.model_dump()
    return await mediate_tool_action(action_dict, workload, db, correlation_id)


@app.post("/demo/dlp", tags=["Legacy Compatibility"])
async def legacy_dlp(request: DLPRequest):
    clean, findings = redact_text_content(request.text, DLPAction.REDACT)
    return {"redacted_text": clean, "findings": findings, "redacted": bool(findings)}


@app.get("/events", tags=["Legacy Compatibility"])
async def legacy_events(
    limit: int = Query(50, ge=1, le=200),
    db: Session = Depends(get_db)
):
    events = query_audit_events(db, limit=limit)
    return {"events": events}


@app.get("/stats", tags=["Legacy Compatibility"])
async def legacy_stats(db: Session = Depends(get_db)):
    return get_dashboard_statistics(db)
