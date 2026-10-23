from fastapi import APIRouter
from app.schemas.gateway import PromptScanRequest, DLPRequest
from app.scanners.prompt import scan_prompt
from app.dlp.engine import redact_text_content, DLPAction

router = APIRouter(prefix="/api/v1/security", tags=["Security Scanners & DLP"])


@router.post("/scan", summary="Scan Prompt for Malicious Instructions")
async def scan_input_prompt(payload: PromptScanRequest):
    """
    Evaluates arbitrary input text against prompt injection, jailbreak,
    and secret extraction heuristics.
    """
    result = scan_prompt(payload.prompt)
    return {
        "is_flagged": result.is_flagged,
        "category": result.category,
        "reason": result.reason,
        "confidence": result.confidence,
        "matched_patterns": result.matched_patterns
    }


@router.post("/dlp", summary="DLP Inspection and Masking Test")
async def test_dlp(payload: DLPRequest):
    """
    Inspects text for PII (emails, cards with Luhn check, phone numbers, SSNs)
    and API secrets/keys, returning redacted text and finding categories.
    """
    action_enum = DLPAction(payload.action or "REDACT")
    clean_text, findings = redact_text_content(payload.text, action_enum)
    return {
        "redacted_text": clean_text,
        "findings": findings,
        "redacted": bool(findings)
    }
