import json, sqlite3
from datetime import datetime, timezone
from pathlib import Path
from .config import settings

def connect():
    if settings.database_path != ":memory:":
        Path(settings.database_path).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(settings.database_path, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with connect() as c:
        c.execute("""CREATE TABLE IF NOT EXISTS audit_events(
          id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT NOT NULL,
          agent_id TEXT NOT NULL, tool TEXT NOT NULL,
          decision TEXT NOT NULL CHECK(decision IN ('ALLOW','BLOCK')),
          reason TEXT NOT NULL, destination TEXT NOT NULL, operation TEXT NOT NULL,
          prompt_flagged INTEGER NOT NULL DEFAULT 0, metadata_json TEXT NOT NULL DEFAULT '{}')""")
        c.execute("CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_events(timestamp)")
        c.commit()

def log_event(agent_id, tool, decision, reason, destination, operation,
              prompt_flagged=False, metadata=None):
    # Never store raw prompts, SQL, or unredacted payloads in audit logs.
    timestamp = datetime.now(timezone.utc).isoformat()
    with connect() as c:
        cur = c.execute("""INSERT INTO audit_events(timestamp,agent_id,tool,decision,reason,
          destination,operation,prompt_flagged,metadata_json) VALUES(?,?,?,?,?,?,?,?,?)""",
          (timestamp, agent_id, tool, decision, reason, destination, operation,
           int(prompt_flagged), json.dumps(metadata or {}, separators=(",", ":"))))
        c.commit()
        event_id = cur.lastrowid
    return {"id": event_id, "timestamp": timestamp, "agent_id": agent_id, "tool": tool,
            "decision": decision, "reason": reason, "destination": destination,
            "operation": operation, "prompt_flagged": prompt_flagged}

def recent_events(limit=50):
    with connect() as c:
        rows = c.execute("SELECT * FROM audit_events ORDER BY id DESC LIMIT ?",
                         (max(1, min(limit, 200)),)).fetchall()
    events = []
    for row in rows:
        item = dict(row); item["prompt_flagged"] = bool(item["prompt_flagged"])
        item["metadata"] = json.loads(item.pop("metadata_json")); events.append(item)
    return events

def stats():
    with connect() as c:
        rows = c.execute("SELECT decision,COUNT(*) n FROM audit_events GROUP BY decision").fetchall()
        total = c.execute("SELECT COUNT(*) FROM audit_events").fetchone()[0]
        flagged = c.execute("SELECT COUNT(*) FROM audit_events WHERE prompt_flagged=1").fetchone()[0]
    counts = {r["decision"].lower(): r["n"] for r in rows}
    return {"total": total, "allowed": counts.get("allow", 0),
            "blocked": counts.get("block", 0), "prompt_flagged": flagged}
