import hashlib
import tempfile
import subprocess
import shutil
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from app.database.session import get_db
from app.database.models import PolicyRecord
from app.schemas.gateway import PolicyValidateRequest
from app.auth.dependencies import get_current_user
from app.database.models import User

router = APIRouter(prefix="/api/v1/policies", tags=["Policy Management"])


@router.get("", summary="List Active Security Policies")
async def list_policies(db: Session = Depends(get_db)):
    """Returns active OPA/Rego policy rules and cryptographic checksums."""
    policies = db.query(PolicyRecord).all()
    return [
        {
            "id": p.id,
            "name": p.name,
            "version": p.version,
            "checksum": p.checksum,
            "is_active": p.is_active,
            "rego_code": p.rego_code,
            "created_at": p.created_at.isoformat() if p.created_at else None,
            "updated_at": p.updated_at.isoformat() if p.updated_at else None,
        }
        for p in policies
    ]


@router.post("/validate", summary="Validate Rego Policy Syntax")
async def validate_policy(
    payload: PolicyValidateRequest,
    current_user: User = Depends(get_current_user)
):
    """
    Validates proposed Rego policy code syntax using the OPA compiler.
    """
    rego_code = payload.rego_code
    checksum = hashlib.sha256(rego_code.encode("utf-8")).hexdigest()

    # Check if opa binary is available locally
    opa_bin = shutil.which("opa") or "/opt/homebrew/bin/opa"
    if not shutil.which("opa") and not __import__("os").path.exists(opa_bin):
        # Basic static parse check
        if "package " not in rego_code or "default allow" not in rego_code:
            return {"valid": False, "error": "Policy must contain package declaration and default allow rule."}
        return {"valid": True, "checksum": checksum, "validator": "static_heuristic"}

    with tempfile.NamedTemporaryFile(suffix=".rego", mode="w", delete=False) as tmp:
        tmp.write(rego_code)
        tmp_path = tmp.name

    try:
        res = subprocess.run([opa_bin, "check", tmp_path], capture_output=True, text=True)
        if res.returncode != 0:
            return {"valid": False, "error": res.stderr.strip() or res.stdout.strip(), "checksum": checksum}
        return {"valid": True, "checksum": checksum, "validator": "opa_compiler"}
    finally:
        __import__("os").unlink(tmp_path)
