from dataclasses import dataclass, field
from typing import Dict, Any, List, Callable, Optional, Awaitable
from pydantic import BaseModel, Field


class ToolDefinition(BaseModel):
    name: str
    description: str
    allowed_operations: List[str]
    permitted_resources: List[str]
    required_workload_scopes: List[str]
    destination_restrictions: List[str]
    data_classification: str = "CONFIDENTIAL"  # PUBLIC, INTERNAL, CONFIDENTIAL, RESTRICTED
    risk_classification: str = "MEDIUM"        # LOW, MEDIUM, HIGH, CRITICAL
    execution_timeout_seconds: float = 5.0
    audit_required: bool = True


class ToolRegistry:
    """Central registry for all tools accessible through the security gateway."""

    def __init__(self):
        self._definitions: Dict[str, ToolDefinition] = {}
        self._executors: Dict[str, Callable[[Dict[str, Any], Any], Awaitable[Any]]] = {}

    def register(
        self,
        definition: ToolDefinition,
        executor: Callable[[Dict[str, Any], Any], Awaitable[Any]]
    ):
        self._definitions[definition.name] = definition
        self._executors[definition.name] = executor

    def get_definition(self, tool_name: str) -> Optional[ToolDefinition]:
        return self._definitions.get(tool_name)

    def get_executor(self, tool_name: str) -> Optional[Callable[[Dict[str, Any], Any], Awaitable[Any]]]:
        return self._executors.get(tool_name)

    def list_tools(self) -> List[ToolDefinition]:
        return list(self._definitions.values())


registry = ToolRegistry()
