from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.database.session import get_db
from app.llm.schemas import AttackScenario, AttackExecutionResult
from app.scenarios.engine import list_attack_scenarios, execute_attack_simulation

router = APIRouter(prefix="/api/v1/simulator", tags=["Attack Studio & Security Simulator"])


class CustomSimulationRequest(BaseModel):
    name: Optional[str] = "Custom Operator Attack"
    prompt: Optional[str] = None
    tool_call: Optional[Dict[str, Any]] = None
    tenant_id: str = "tenant-alpha"


@router.get("/scenarios", summary="List Pre-configured Attack Scenarios", response_model=List[AttackScenario])
async def get_scenarios():
    """Returns catalog of pre-configured adversarial test vectors across prompt, IAM, SSRF, and data security."""
    return list_attack_scenarios()


@router.post("/run/{scenario_id}", summary="Execute Attack Simulation Scenario", response_model=AttackExecutionResult)
async def run_scenario(
    scenario_id: str,
    request: Request,
    db: Session = Depends(get_db)
):
    """
    Executes a structured attack scenario through the live Zero-Trust Gateway,
    tracking the 12-step pipeline decision and returning execution traces.
    """
    return await execute_attack_simulation(scenario_id=scenario_id, db=db)


@router.post("/custom", summary="Execute Custom Attack Simulation", response_model=AttackExecutionResult)
async def run_custom_simulation(
    payload: CustomSimulationRequest,
    request: Request,
    db: Session = Depends(get_db)
):
    """
    Allows security operators to craft arbitrary prompts or tool payloads
    and simulate real-time zero-trust enforcement.
    """
    custom_payload = {}
    if payload.prompt:
        custom_payload["prompt"] = payload.prompt
    if payload.tool_call:
        custom_payload["tool_call"] = payload.tool_call

    return await execute_attack_simulation(
        scenario_id="custom_attack",
        db=db,
        custom_payload=custom_payload,
        tenant_id=payload.tenant_id
    )
