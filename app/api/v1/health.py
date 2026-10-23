from fastapi import APIRouter, Depends, status, Response
from sqlalchemy.orm import Session
from sqlalchemy import text
import httpx
from app.database.session import get_db
from app.core.config import settings

router = APIRouter(tags=["Health & Probes"])


@router.get("/health/live", summary="Liveness probe")
async def liveness():
    """Returns 200 when application process is running."""
    return {"status": "alive", "timestamp": settings.VERSION}


@router.get("/health/ready", summary="Readiness probe")
async def readiness(response: Response, db: Session = Depends(get_db)):
    """
    Checks connectivity to database and OPA policy engine.
    Fails readiness with 503 if core dependencies are unavailable.
    """
    db_ok = False
    try:
        db.execute(text("SELECT 1"))
        db_ok = True
    except Exception:
        db_ok = False

    opa_ok = False
    try:
        async with httpx.AsyncClient(timeout=0.3) as client:
            opa_res = await client.get(settings.OPA_URL.rsplit("/v1/", 1)[0] + "/health")
            opa_ok = (opa_res.status_code == 200)
    except Exception:
        opa_ok = False

    is_ready = db_ok and (opa_ok or not settings.OPA_FAIL_CLOSED)
    if not is_ready:
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE

    return {
        "status": "ready" if is_ready else "degraded",
        "database": "connected" if db_ok else "unreachable",
        "policy_engine": "connected" if opa_ok else ("offline_local_fallback" if not settings.OPA_FAIL_CLOSED else "unreachable"),
        "environment": settings.ENVIRONMENT,
        "opa_fail_closed": settings.OPA_FAIL_CLOSED
    }
