from typing import List
from fastapi import APIRouter, Depends, HTTPException, Request, Response
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session

from app.database.session import get_db
from app.llm.schemas import (
    ChatCompletionRequest,
    ChatCompletionResponse,
    ProviderInfo
)
from app.llm.providers import get_available_providers
from app.llm.proxy import mediate_chat_completion, mediate_chat_stream

router = APIRouter(prefix="/api/v1/llm", tags=["LLM Gateway & Streaming Proxy"])


@router.get("/providers", summary="List Available LLM Providers", response_model=List[ProviderInfo])
async def list_providers():
    """
    Returns inventory of available LLM providers (Google Gemini, OpenAI,
    Anthropic Claude, and Deterministic Zero-Trust Simulator), along with model
    support and API key status.
    """
    return get_available_providers()


@router.post("/chat", summary="Zero-Trust Mediated Chat Completion")
async def chat_completion(
    payload: ChatCompletionRequest,
    request: Request,
    db: Session = Depends(get_db)
):
    """
    Routes chat completion through the Zero-Trust LLM Mediation Gateway:
    1. Evaluates prompts against adversarial & injection heuristics.
    2. Redacts sensitive PII & cloud credentials prior to model dispatch.
    3. Issues canary token tracking.
    4. Intercepts and mediates autonomous tool calls via OPA and SSRF guards.
    5. Applies post-inference DLP sanitization.
    6. Appends cryptographic audit hash receipt.
    Supports Server-Sent Events (SSE) streaming when stream=true.
    """
    correlation_id = getattr(request.state, "correlation_id", None)

    if payload.stream:
        return StreamingResponse(
            mediate_chat_stream(payload, db, correlation_id),
            media_type="text/event-stream",
            headers={
                "Cache-Control": "no-cache",
                "Connection": "keep-alive",
                "X-Accel-Buffering": "no"
            }
        )

    return await mediate_chat_completion(payload, db, correlation_id)
