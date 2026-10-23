import logging
from typing import Dict, Any, Optional
import httpx
from app.core.config import settings
from app.network.ssrf import validate_destination_safety

logger = logging.getLogger(__name__)


class ControlledHTTPClient:
    """
    Zero-Trust Outbound HTTP Client with strict SSRF defense,
    DNS validation, payload bounding, and redirect revalidation.
    """

    def __init__(
        self,
        allowed_domains: Optional[list[str]] = None,
        timeout: float = settings.OUTBOUND_HTTP_TIMEOUT_SECONDS,
        max_bytes: int = settings.OUTBOUND_MAX_RESPONSE_BYTES
    ):
        self.allowed_domains = allowed_domains or settings.ALLOWED_OUTBOUND_DOMAINS
        self.timeout = timeout
        self.max_bytes = max_bytes

    async def execute_request(
        self,
        method: str,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        json_data: Optional[Any] = None,
        max_redirects: int = 2
    ) -> Dict[str, Any]:
        """
        Executes a controlled outbound HTTP request.
        Fails closed on any SSRF or policy violation.
        """
        method = method.upper()
        if method not in ("GET", "POST", "HEAD"):
            raise ValueError(f"HTTP method '{method}' is not permitted for egress tools")

        current_url = url
        redirects_followed = 0

        async with httpx.AsyncClient(follow_redirects=False, timeout=self.timeout) as client:
            while True:
                # 1. Strictly validate destination safety before opening network socket
                normalized_url, hostname, safe_ips = validate_destination_safety(
                    current_url, self.allowed_domains
                )

                req_headers = (headers or {}).copy()
                req_headers["User-Agent"] = "ZeroTrustAIGateway/1.0"

                # 2. Issue request
                response = await client.request(
                    method=method,
                    url=normalized_url,
                    headers=req_headers,
                    json=json_data,
                )

                # 3. Handle redirects securely
                if response.is_redirect:
                    redirects_followed += 1
                    if redirects_followed > max_redirects:
                        raise ValueError("ssrf_excessive_redirects")

                    location = response.headers.get("location")
                    if not location:
                        raise ValueError("ssrf_missing_redirect_location")

                    # Resolve relative redirects safely
                    next_url = str(response.url.join(location))
                    logger.info("Outbound redirect detected: %s -> %s (re-validating)", current_url, next_url)
                    current_url = next_url
                    continue

                # 4. Read body with byte-level bounding to prevent memory exhaustion / zip bombs
                content_bytes = bytearray()
                async for chunk in response.aiter_bytes(chunk_size=4096):
                    content_bytes.extend(chunk)
                    if len(content_bytes) > self.max_bytes:
                        raise ValueError(f"Outbound response exceeded maximum payload limit of {self.max_bytes} bytes")

                body_text = content_bytes.decode("utf-8", errors="replace")

                # Parse JSON if applicable
                body_json = None
                content_type = response.headers.get("content-type", "")
                if "application/json" in content_type:
                    try:
                        import json
                        body_json = json.loads(body_text)
                    except Exception:
                        pass

                return {
                    "status_code": response.status_code,
                    "headers": dict(response.headers),
                    "text": body_text,
                    "json": body_json,
                    "url": str(response.url),
                    "destination_ip": safe_ips[0] if safe_ips else None
                }
