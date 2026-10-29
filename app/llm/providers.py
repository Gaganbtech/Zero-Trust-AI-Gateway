import json
import logging
import uuid
import asyncio
from abc import ABC, abstractmethod
from typing import Any, AsyncIterator, Dict, List, Optional, Tuple

import httpx

from app.core.config import settings
from app.llm.schemas import ChatMessage, ToolCall, ToolCallFunction, ProviderInfo

logger = logging.getLogger(__name__)

GATEWAY_TOOL_DECLARATIONS = [
    {
        "name": "db_query",
        "description": "Executes parameterized read-only query on internal database scoped to tenant.",
        "parameters": {
            "type": "object",
            "properties": {
                "table": {"type": "string", "enum": ["customers"], "description": "Database table to query"},
                "columns": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Columns allowlist (id, name, email, phone, card_number, account_balance)"
                },
                "limit": {"type": "integer", "description": "Max rows to return (capped at 20)"}
            },
            "required": ["table"]
        }
    },
    {
        "name": "weather",
        "description": "Fetches current weather and atmospheric conditions for a target city.",
        "parameters": {
            "type": "object",
            "properties": {
                "city": {"type": "string", "description": "City name, e.g. Bengaluru, Seattle"}
            },
            "required": ["city"]
        }
    },
    {
        "name": "safe_http",
        "description": "Issues SSRF-guarded outbound HTTP GET request to approved external domains.",
        "parameters": {
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "Target external URL"}
            },
            "required": ["url"]
        }
    },
    {
        "name": "cspm_scan",
        "description": "Runs an instant Cloud Security Posture Management evaluation for AI environments.",
        "parameters": {
            "type": "object",
            "properties": {
                "environment": {"type": "string", "enum": ["AWS", "Azure", "GCP", "Kubernetes", "ALL"]}
            }
        }
    }
]


class BaseLLMProvider(ABC):
    """Abstract interface for Zero-Trust Mediated LLM Providers."""

    def __init__(self, model_name: str):
        self.model_name = model_name

    @abstractmethod
    async def generate(
        self,
        messages: List[ChatMessage],
        tools_enabled: bool = True,
        temperature: float = 0.7,
        max_tokens: int = 1024
    ) -> Tuple[ChatMessage, List[ToolCall]]:
        pass

    @abstractmethod
    async def generate_stream(
        self,
        messages: List[ChatMessage],
        tools_enabled: bool = True,
        temperature: float = 0.7,
        max_tokens: int = 1024
    ) -> AsyncIterator[str]:
        pass


class MockZeroTrustProvider(BaseLLMProvider):
    """
    High-fidelity deterministic autonomous agent simulator.
    Interprets intent, triggers realistic tool calls, and demonstrates zero-trust mediation
    without requiring third-party API keys or incurring costs.
    """

    async def generate(
        self,
        messages: List[ChatMessage],
        tools_enabled: bool = True,
        temperature: float = 0.7,
        max_tokens: int = 1024
    ) -> Tuple[ChatMessage, List[ToolCall]]:
        last_user_msg = next((m.content or "" for m in reversed(messages) if m.role == "user"), "")
        lower = last_user_msg.lower()

        tool_calls: List[ToolCall] = []

        # Intent 1: Database Query for Customers/Accounts
        if tools_enabled and any(k in lower for k in ["customer", "account", "user", "balance", "client", "database", "record"]):
            call_id = f"call_{uuid.uuid4().hex[:8]}"
            tool_calls.append(
                ToolCall(
                    id=call_id,
                    type="function",
                    function=ToolCallFunction(
                        name="db_query",
                        arguments=json.dumps({
                            "table": "customers",
                            "columns": ["id", "name", "email", "phone", "account_balance"],
                            "limit": 5
                        })
                    )
                )
            )
            content = "I will query the tenant customer records through the zero-trust database gateway."

        # Intent 2: Weather Inquiries
        elif tools_enabled and any(k in lower for k in ["weather", "temperature", "forecast", "climate"]):
            call_id = f"call_{uuid.uuid4().hex[:8]}"
            city = "Bengaluru"
            for word in ["seattle", "bengaluru", "london", "tokyo", "paris", "austin"]:
                if word in lower:
                    city = word.capitalize()
                    break
            tool_calls.append(
                ToolCall(
                    id=call_id,
                    type="function",
                    function=ToolCallFunction(
                        name="weather",
                        arguments=json.dumps({"city": city})
                    )
                )
            )
            content = f"Fetching current verified weather data for {city} via safe egress."

        # Intent 3: Cloud Security Posture (CSPM)
        elif tools_enabled and any(k in lower for k in ["cspm", "posture", "cloud security", "compliance", "audit"]):
            call_id = f"call_{uuid.uuid4().hex[:8]}"
            tool_calls.append(
                ToolCall(
                    id=call_id,
                    type="function",
                    function=ToolCallFunction(
                        name="cspm_scan",
                        arguments=json.dumps({"environment": "ALL"})
                    )
                )
            )
            content = "Triggering a zero-trust AI-CSPM posture assessment across cloud environments."

        # Intent 4: Outbound HTTP / External Request
        elif tools_enabled and any(k in lower for k in ["http", "egress", "api", "curl", "fetch", "web", "site"]):
            call_id = f"call_{uuid.uuid4().hex[:8]}"
            tool_calls.append(
                ToolCall(
                    id=call_id,
                    type="function",
                    function=ToolCallFunction(
                        name="safe_http",
                        arguments=json.dumps({"url": "https://httpbin.org/get"})
                    )
                )
            )
            content = "Executing SSRF-guarded outbound HTTP egress to approved external endpoint."

        # Default: Informative Security Response
        else:
            content = (
                f"Zero-Trust Gateway Online. Your instruction ('{last_user_msg[:60]}...') "
                f"was evaluated under tenant boundary and runtime policies. "
                f"All prompt inputs are inspected for injection heuristics, DLP leakage, and IAM scopes "
                f"before any autonomous tool execution or egress is authorized."
            )

        return (
            ChatMessage(
                role="assistant",
                content=content,
                tool_calls=tool_calls if tool_calls else None
            ),
            tool_calls
        )

    async def generate_stream(
        self,
        messages: List[ChatMessage],
        tools_enabled: bool = True,
        temperature: float = 0.7,
        max_tokens: int = 1024
    ) -> AsyncIterator[str]:
        msg, _ = await self.generate(messages, tools_enabled, temperature, max_tokens)
        text = msg.content or ""
        words = text.split(" ")
        for i, word in enumerate(words):
            yield word + (" " if i < len(words) - 1 else "")
            await asyncio.sleep(0.015)


class GeminiProvider(BaseLLMProvider):
    """Google Gemini Provider using official API surface."""

    def __init__(self, model_name: str = "gemini-3.6-flash", api_key: Optional[str] = None):
        super().__init__(model_name)
        self.api_key = api_key or settings.GEMINI_API_KEY
        self.base_url = "https://generativelanguage.googleapis.com/v1beta"

    async def generate(
        self,
        messages: List[ChatMessage],
        tools_enabled: bool = True,
        temperature: float = 0.7,
        max_tokens: int = 1024
    ) -> Tuple[ChatMessage, List[ToolCall]]:
        if not self.api_key:
            logger.warning("GEMINI_API_KEY not configured. Falling back to MockZeroTrustProvider.")
            mock = MockZeroTrustProvider(self.model_name)
            return await mock.generate(messages, tools_enabled, temperature, max_tokens)

        contents = []
        for m in messages:
            role = "user" if m.role in ("user", "system") else "model"
            contents.append({"role": role, "parts": [{"text": m.content or ""}]})

        payload: Dict[str, Any] = {
            "contents": contents,
            "generationConfig": {
                "temperature": temperature,
                "maxOutputTokens": max_tokens
            }
        }

        url = f"{self.base_url}/models/{self.model_name}:generateContent?key={self.api_key}"
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.post(url, json=payload)
            if resp.status_code != 200:
                raise RuntimeError(f"Gemini API error ({resp.status_code}): {resp.text}")
            data = resp.json()

        candidates = data.get("candidates", [])
        if not candidates:
            return ChatMessage(role="assistant", content=""), []

        content_part = candidates[0].get("content", {}).get("parts", [{}])[0]
        text = content_part.get("text", "")
        return ChatMessage(role="assistant", content=text), []

    async def generate_stream(
        self,
        messages: List[ChatMessage],
        tools_enabled: bool = True,
        temperature: float = 0.7,
        max_tokens: int = 1024
    ) -> AsyncIterator[str]:
        if not self.api_key:
            mock = MockZeroTrustProvider(self.model_name)
            async for chunk in mock.generate_stream(messages, tools_enabled, temperature, max_tokens):
                yield chunk
            return

        msg, _ = await self.generate(messages, tools_enabled, temperature, max_tokens)
        yield msg.content or ""


class OpenAIProvider(BaseLLMProvider):
    """OpenAI / OpenAI-Compatible Provider."""

    def __init__(self, model_name: str = "gpt-4o-mini", api_key: Optional[str] = None):
        super().__init__(model_name)
        self.api_key = api_key or settings.OPENAI_API_KEY
        self.base_url = "https://api.openai.com/v1"

    async def generate(
        self,
        messages: List[ChatMessage],
        tools_enabled: bool = True,
        temperature: float = 0.7,
        max_tokens: int = 1024
    ) -> Tuple[ChatMessage, List[ToolCall]]:
        if not self.api_key:
            mock = MockZeroTrustProvider(self.model_name)
            return await mock.generate(messages, tools_enabled, temperature, max_tokens)

        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }
        formatted_messages = [
            {"role": m.role, "content": m.content or ""} for m in messages
        ]
        payload: Dict[str, Any] = {
            "model": self.model_name,
            "messages": formatted_messages,
            "temperature": temperature,
            "max_tokens": max_tokens
        }

        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.post(f"{self.base_url}/chat/completions", headers=headers, json=payload)
            if resp.status_code != 200:
                raise RuntimeError(f"OpenAI API error ({resp.status_code}): {resp.text}")
            data = resp.json()

        choice = data["choices"][0]["message"]
        return ChatMessage(role="assistant", content=choice.get("content", "")), []

    async def generate_stream(
        self,
        messages: List[ChatMessage],
        tools_enabled: bool = True,
        temperature: float = 0.7,
        max_tokens: int = 1024
    ) -> AsyncIterator[str]:
        if not self.api_key:
            mock = MockZeroTrustProvider(self.model_name)
            async for chunk in mock.generate_stream(messages, tools_enabled, temperature, max_tokens):
                yield chunk
            return

        msg, _ = await self.generate(messages, tools_enabled, temperature, max_tokens)
        yield msg.content or ""


class AnthropicProvider(BaseLLMProvider):
    """Anthropic Claude Provider."""

    def __init__(self, model_name: str = "claude-3-5-haiku-20241022", api_key: Optional[str] = None):
        super().__init__(model_name)
        self.api_key = api_key or settings.ANTHROPIC_API_KEY
        self.base_url = "https://api.anthropic.com/v1"

    async def generate(
        self,
        messages: List[ChatMessage],
        tools_enabled: bool = True,
        temperature: float = 0.7,
        max_tokens: int = 1024
    ) -> Tuple[ChatMessage, List[ToolCall]]:
        if not self.api_key:
            mock = MockZeroTrustProvider(self.model_name)
            return await mock.generate(messages, tools_enabled, temperature, max_tokens)

        headers = {
            "x-api-key": self.api_key,
            "anthropic-version": "2023-06-01",
            "content-type": "application/json"
        }
        system_text = ""
        user_messages = []
        for m in messages:
            if m.role == "system":
                system_text += (m.content or "") + "\n"
            else:
                user_messages.append({"role": m.role, "content": m.content or ""})

        payload: Dict[str, Any] = {
            "model": self.model_name,
            "messages": user_messages,
            "max_tokens": max_tokens,
            "temperature": temperature
        }
        if system_text:
            payload["system"] = system_text.strip()

        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.post(f"{self.base_url}/messages", headers=headers, json=payload)
            if resp.status_code != 200:
                raise RuntimeError(f"Anthropic API error ({resp.status_code}): {resp.text}")
            data = resp.json()

        text = ""
        for block in data.get("content", []):
            if block.get("type") == "text":
                text += block.get("text", "")
        return ChatMessage(role="assistant", content=text), []

    async def generate_stream(
        self,
        messages: List[ChatMessage],
        tools_enabled: bool = True,
        temperature: float = 0.7,
        max_tokens: int = 1024
    ) -> AsyncIterator[str]:
        if not self.api_key:
            mock = MockZeroTrustProvider(self.model_name)
            async for chunk in mock.generate_stream(messages, tools_enabled, temperature, max_tokens):
                yield chunk
            return

        msg, _ = await self.generate(messages, tools_enabled, temperature, max_tokens)
        yield msg.content or ""


def get_available_providers() -> List[ProviderInfo]:
    """Returns inventory of supported LLM providers and operational statuses."""
    return [
        ProviderInfo(
            id="mock",
            name="Deterministic Zero-Trust Simulator",
            available=True,
            requires_api_key=False,
            has_api_key=True,
            recommended_model="zero-trust-simulator-v1",
            supported_models=["zero-trust-simulator-v1", "autonomous-security-agent-v1"],
            supports_streaming=True,
            supports_tools=True
        ),
        ProviderInfo(
            id="gemini",
            name="Google Gemini",
            available=True,
            requires_api_key=True,
            has_api_key=bool(settings.GEMINI_API_KEY),
            recommended_model="gemini-3.6-flash",
            supported_models=["gemini-3.6-flash", "gemini-3.5-flash-lite", "gemini-3.1-pro-preview"],
            supports_streaming=True,
            supports_tools=True
        ),
        ProviderInfo(
            id="openai",
            name="OpenAI",
            available=True,
            requires_api_key=True,
            has_api_key=bool(settings.OPENAI_API_KEY),
            recommended_model="gpt-4o-mini",
            supported_models=["gpt-4o", "gpt-4o-mini", "o3-mini"],
            supports_streaming=True,
            supports_tools=True
        ),
        ProviderInfo(
            id="anthropic",
            name="Anthropic Claude",
            available=True,
            requires_api_key=True,
            has_api_key=bool(settings.ANTHROPIC_API_KEY),
            recommended_model="claude-3-5-haiku-20241022",
            supported_models=["claude-3-7-sonnet-20250219", "claude-3-5-haiku-20241022"],
            supports_streaming=True,
            supports_tools=True
        )
    ]


def get_provider(provider_id: Optional[str] = None, model_name: Optional[str] = None) -> BaseLLMProvider:
    """Factory creating an authenticated LLM provider instance."""
    provider_id = (provider_id or settings.DEFAULT_LLM_PROVIDER).lower()

    if provider_id == "gemini":
        model = model_name or "gemini-3.6-flash"
        return GeminiProvider(model_name=model)
    elif provider_id == "openai":
        model = model_name or "gpt-4o-mini"
        return OpenAIProvider(model_name=model)
    elif provider_id == "anthropic":
        model = model_name or "claude-3-5-haiku-20241022"
        return AnthropicProvider(model_name=model)
    else:
        model = model_name or "zero-trust-simulator-v1"
        return MockZeroTrustProvider(model_name=model)
