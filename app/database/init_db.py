import json
import hashlib
from pathlib import Path
from app.database.session import engine, SessionLocal, Base
from app.database.models import Customer, AgentRegistryItem, User, PolicyRecord
from app.auth.security import hash_password


def init_database():
    """Initializes tables and seeds initial data if missing."""
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        # 1. Seed Synthetic Customers if empty
        if db.query(Customer).count() == 0:
            customers = [
                Customer(
                    tenant_id="tenant-alpha",
                    name="Asha Rao",
                    email="asha.rao@example.com",
                    phone="+91 98765 43210",
                    card_number="4111111111111111",
                    account_balance=12500.50,
                ),
                Customer(
                    tenant_id="tenant-alpha",
                    name="Kiran Das",
                    email="kiran.das@example.com",
                    phone="+91 91234 56789",
                    card_number="5555555555554444",
                    account_balance=3400.00,
                ),
                Customer(
                    tenant_id="tenant-alpha",
                    name="Carlos Mendez",
                    email="carlos.m@example.org",
                    phone="+1 415 555 0192",
                    card_number="4000000000000002",
                    account_balance=8920.10,
                ),
                Customer(
                    tenant_id="tenant-beta",
                    name="Elena Rostova",
                    email="elena.r@finance.example",
                    phone="+44 20 7946 0912",
                    card_number="4222222222222",
                    account_balance=450000.00,
                ),
                Customer(
                    tenant_id="tenant-beta",
                    name="Taro Tanaka",
                    email="taro.tanaka@tokyo.example",
                    phone="+81 3 5555 0143",
                    card_number="4111111111111111",
                    account_balance=78000.00,
                ),
            ]
            db.add_all(customers)

        # 2. Seed Registered Agents if empty
        if db.query(AgentRegistryItem).count() == 0:
            agents = [
                AgentRegistryItem(
                    id="demo-agent",
                    name="Deterministic Local Demo Agent",
                    tenant_id="tenant-alpha",
                    description="Standard local demo agent with read-only access to tenant-alpha customer records.",
                    status="ACTIVE",
                    allowed_tools_json=json.dumps(["db_query", "weather", "safe_http"]),
                    scopes_json=json.dumps(["customer:read", "weather:read", "http:egress"]),
                ),
                AgentRegistryItem(
                    id="agent-analytics-01",
                    name="Tenant-Alpha Analytics Agent",
                    tenant_id="tenant-alpha",
                    description="Production data warehouse analytics agent for tenant-alpha.",
                    status="ACTIVE",
                    allowed_tools_json=json.dumps(["db_query"]),
                    scopes_json=json.dumps(["customer:read"]),
                ),
                AgentRegistryItem(
                    id="agent-beta-support",
                    name="Tenant-Beta Support Agent",
                    tenant_id="tenant-beta",
                    description="Customer support automation agent strictly bound to tenant-beta.",
                    status="ACTIVE",
                    allowed_tools_json=json.dumps(["db_query", "weather"]),
                    scopes_json=json.dumps(["customer:read", "weather:read"]),
                ),
                AgentRegistryItem(
                    id="agent-suspended-99",
                    name="Compromised Suspended Agent",
                    tenant_id="tenant-alpha",
                    description="Agent quarantined due to suspicious automated tool invocation behavior.",
                    status="SUSPENDED",
                    allowed_tools_json=json.dumps([]),
                    scopes_json=json.dumps([]),
                ),
            ]
            db.add_all(agents)

        # 3. Seed Operator Dashboard Users if empty
        if db.query(User).count() == 0:
            users = [
                User(
                    id="user-admin-01",
                    username="admin",
                    hashed_password=hash_password("AdminSecure2026!"),
                    role="admin",
                    is_active=True,
                ),
                User(
                    id="user-analyst-01",
                    username="analyst",
                    hashed_password=hash_password("AnalystSecure2026!"),
                    role="analyst",
                    is_active=True,
                ),
                User(
                    id="user-auditor-01",
                    username="auditor",
                    hashed_password=hash_password("AuditorSecure2026!"),
                    role="auditor",
                    is_active=True,
                ),
                User(
                    id="user-viewer-01",
                    username="viewer",
                    hashed_password=hash_password("ViewerSecure2026!"),
                    role="viewer",
                    is_active=True,
                ),
            ]
            db.add_all(users)

        # 4. Seed Active Rego Policy Record if empty
        if db.query(PolicyRecord).count() == 0:
            rego_path = Path(__file__).resolve().parent.parent.parent / "policies" / "agent.rego"
            if rego_path.exists():
                rego_code = rego_path.read_text(encoding="utf-8")
            else:
                rego_code = "package ai_gateway\n\ndefault allow := false\n"
            
            checksum = hashlib.sha256(rego_code.encode("utf-8")).hexdigest()
            policy_record = PolicyRecord(
                id="policy-rego-v1",
                name="AI Gateway Zero-Trust Runtime Policy",
                version="1.0.0",
                rego_code=rego_code,
                is_active=True,
                checksum=checksum,
            )
            db.add(policy_record)

        db.commit()
    finally:
        db.close()
