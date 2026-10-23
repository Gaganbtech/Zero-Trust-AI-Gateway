import logging
from typing import Dict, Any, List
from sqlalchemy.orm import Session
from app.database.session import SessionLocal
from app.database.models import Customer

logger = logging.getLogger(__name__)

ALLOWED_COLUMNS = {
    "id",
    "tenant_id",
    "name",
    "email",
    "phone",
    "card_number",
    "account_balance",
}


async def execute_customer_query(args: Dict[str, Any], context: Any) -> List[Dict[str, Any]]:
    """
    Executes a strictly parameterized, tenant-isolated query on customer records.
    Never executes raw or model-generated SQL strings.
    """
    tenant_id = getattr(context, "tenant_id", "default-tenant")

    # 1. Validate requested columns
    columns = args.get("columns", ["id", "name", "email"])
    if not isinstance(columns, list) or not columns:
        raise ValueError("Invalid columns specification: must be a non-empty list")
    
    for col in columns:
        if col not in ALLOWED_COLUMNS:
            raise ValueError(f"Disallowed column requested: '{col}'")

    # 2. Validate limit and pagination
    limit = args.get("limit", 10)
    if not isinstance(limit, int) or isinstance(limit, bool) or not (1 <= limit <= 20):
        raise ValueError("Invalid query limit: must be an integer between 1 and 20")

    # 3. Parameterized query with strict tenant boundary
    db: Session = SessionLocal()
    try:
        query = db.query(Customer).filter(Customer.tenant_id == tenant_id)

        # Optional name/email filter (parameterized)
        search_filter = args.get("search")
        if search_filter and isinstance(search_filter, str):
            clean_search = search_filter.strip()[:100]
            query = query.filter(Customer.name.ilike(f"%{clean_search}%"))

        rows = query.limit(limit).all()

        results = []
        for row in rows:
            record = {}
            for col in columns:
                record[col] = getattr(row, col)
            results.append(record)

        return results
    finally:
        db.close()
