import hmac
import hashlib
import json
from typing import Dict, Any, Tuple
from app.core.config import settings

GENESIS_HASH = "0" * 64


def calculate_event_hash(
    previous_hash: str,
    event_data: Dict[str, Any]
) -> str:
    """
    Computes a cryptographic HMAC-SHA256 hash for an audit event
    bound to the previous event's hash, forming an immutable hash chain.
    """
    canonical_payload = {
        "previous_hash": previous_hash,
        "timestamp": event_data["timestamp"],
        "agent_id": event_data["agent_id"],
        "tenant_id": event_data["tenant_id"],
        "tool": event_data["tool"],
        "operation": event_data["operation"],
        "destination": event_data["destination"],
        "decision": event_data["decision"],
        "reason": event_data["reason"],
    }
    canonical_str = json.dumps(canonical_payload, sort_keys=True, separators=(",", ":"))
    return hmac.new(
        settings.AUDIT_CHAIN_SALT.encode("utf-8"),
        canonical_str.encode("utf-8"),
        hashlib.sha256
    ).hexdigest()
