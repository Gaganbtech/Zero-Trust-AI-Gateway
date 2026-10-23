import pytest
from app.auth.workload import VerifiedWorkload
from app.tools.db_tool import execute_customer_query


@pytest.mark.asyncio
async def test_parameterized_query_success(client):
    workload = VerifiedWorkload(
        agent_id="demo-agent",
        tenant_id="tenant-alpha",
        scopes=["customer:read"]
    )
    results = await execute_customer_query({"columns": ["id", "name", "email"], "limit": 5}, workload)
    assert len(results) > 0
    assert "name" in results[0]
    assert "email" in results[0]


@pytest.mark.asyncio
async def test_tenant_isolation_enforced(client):
    # Tenant Alpha should only see tenant-alpha customers (e.g. Asha Rao, Kiran Das)
    workload_alpha = VerifiedWorkload(
        agent_id="agent-alpha",
        tenant_id="tenant-alpha",
        scopes=["customer:read"]
    )
    alpha_results = await execute_customer_query({"columns": ["name", "email"], "limit": 10}, workload_alpha)
    alpha_names = [r["name"] for r in alpha_results]
    assert "Asha Rao" in alpha_names
    # Elena Rostova is tenant-beta and must NEVER appear in tenant-alpha results
    assert "Elena Rostova" not in alpha_names

    # Tenant Beta should only see tenant-beta customers (Elena Rostova, Taro Tanaka)
    workload_beta = VerifiedWorkload(
        agent_id="agent-beta",
        tenant_id="tenant-beta",
        scopes=["customer:read"]
    )
    beta_results = await execute_customer_query({"columns": ["name", "email"], "limit": 10}, workload_beta)
    beta_names = [r["name"] for r in beta_results]
    assert "Elena Rostova" in beta_names
    assert "Asha Rao" not in beta_names


@pytest.mark.asyncio
async def test_disallowed_column_blocked():
    workload = VerifiedWorkload(agent_id="demo-agent", tenant_id="tenant-alpha")
    with pytest.raises(ValueError) as exc:
        await execute_customer_query({"columns": ["name", "unauthorized_column_x"]}, workload)
    assert "Disallowed column" in str(exc.value)


@pytest.mark.asyncio
async def test_excessive_limit_rejected():
    workload = VerifiedWorkload(agent_id="demo-agent", tenant_id="tenant-alpha")
    with pytest.raises(ValueError) as exc:
        await execute_customer_query({"columns": ["name"], "limit": 500}, workload)
    assert "limit" in str(exc.value)
