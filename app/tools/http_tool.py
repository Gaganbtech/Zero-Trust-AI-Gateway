from typing import Dict, Any
from app.network.client import ControlledHTTPClient


async def execute_safe_http_tool(args: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """
    Executes controlled outbound HTTP egress via ControlledHTTPClient.
    """
    url = args.get("url")
    if not url or not isinstance(url, str):
        raise ValueError("Missing or invalid target 'url' in tool arguments")

    method = args.get("method", "GET")
    headers = args.get("headers", {})
    body = args.get("body")

    client = ControlledHTTPClient()
    return await client.execute_request(
        method=method,
        url=url,
        headers=headers,
        json_data=body
    )
