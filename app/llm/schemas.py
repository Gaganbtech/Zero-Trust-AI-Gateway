from typing import Any, Dict, List, Optional, Union
from pydantic import BaseModel, Field


class ToolCallFunction(BaseModel):
    name: str
    arguments: str  # JSON string of arguments


class ToolCall(BaseModel):
    id: str = Field(default_factory=lambda: "call_auto_generated")
    type: str = "function"
    function: ToolCallFunction


class ChatMessage(BaseModel):
    role: str = Field(pattern="^(system|user|assistant|tool)$")
    content: Optional[str] = None
    name: Optional[str] = None
    tool_call_id: Optional[str] = None
    tool_calls: Optional[List[ToolCall]] = None


class ChatCompletionRequest(BaseModel):
    messages: List[ChatMessage] = Field(min_length=1)
    provider: Optional[str] = Field(default=None, description="mock, gemini, openai, anthropic")
    model: Optional[str] = Field(default=None, description="Model identifier")
    stream: bool = Field(default=False, description="Enable Server-Sent Events (SSE) streaming")
    temperature: float = Field(default=0.7, ge=0.0, le=2.0)
    max_tokens: int = Field(default=1024, ge=1, le=8192)
    tenant_id: str = Field(default="tenant-alpha", max_length=100)
    agent_id: str = Field(default="demo-agent", max_length=100)
    tools_enabled: bool = Field(default=True, description="Allow LLM autonomous tool calling")


class ToolExecutionTrace(BaseModel):
    tool_call_id: str
    tool: str
    operation: str
    destination: str
    args: Dict[str, Any]
    decision: str
    status_code: int
    result: Optional[Any] = None
    dlp_redacted: bool = False
    audit_event_id: Optional[str] = None
    error: Optional[str] = None


class ChatSecurityMetadata(BaseModel):
    prompt_scan_passed: bool = True
    input_dlp_redacted: bool = False
    output_dlp_redacted: bool = False
    canary_token_verified: bool = True
    audit_event_id: Optional[str] = None
    correlation_id: Optional[str] = None
    policy_evaluation_ms: float = 0.0
    tools_mediated_count: int = 0


class ChatCompletionResponse(BaseModel):
    id: str
    provider: str
    model: str
    message: ChatMessage
    finish_reason: str = "stop"
    security: ChatSecurityMetadata
    tool_executions: List[ToolExecutionTrace] = Field(default_factory=list)


class ProviderInfo(BaseModel):
    id: str
    name: str
    available: bool
    requires_api_key: bool
    has_api_key: bool
    recommended_model: str
    supported_models: List[str]
    supports_streaming: bool = True
    supports_tools: bool = True


class AttackScenario(BaseModel):
    id: str
    name: str
    category: str
    threat_level: str = Field(pattern="^(CRITICAL|HIGH|MEDIUM|LOW)$")
    description: str
    attack_vector: str
    prompt: Optional[str] = None
    tool_call: Optional[Dict[str, Any]] = None
    expected_decision: str = "BLOCK"
    expected_blocked_step: int
    expected_blocked_step_name: str


class PipelineStepTrace(BaseModel):
    step_number: int
    name: str
    status: str = Field(pattern="^(PASSED|BLOCKED|SKIPPED)$")
    details: str
    latency_ms: float = 0.0


class AttackExecutionResult(BaseModel):
    scenario_id: str
    name: str
    category: str
    threat_level: str
    decision: str  # ALLOW or BLOCK
    status_code: int
    blocked_step: Optional[int] = None
    blocked_step_name: Optional[str] = None
    reason: str
    duration_ms: float
    pipeline_trace: List[PipelineStepTrace]
    audit_event_id: Optional[str] = None
    remediation_guidance: str
