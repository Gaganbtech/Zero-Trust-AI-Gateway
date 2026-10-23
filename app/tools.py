import sqlite3
from pathlib import Path
DB = Path(__file__).resolve().parent.parent / "demo.db"

def init_demo_db():
    with sqlite3.connect(DB) as c:
        c.execute("""CREATE TABLE IF NOT EXISTS customers(
          id INTEGER PRIMARY KEY, name TEXT NOT NULL, email TEXT NOT NULL,
          phone TEXT NOT NULL, card_number TEXT NOT NULL)""")
        if c.execute("SELECT COUNT(*) FROM customers").fetchone()[0] == 0:
            c.executemany("INSERT INTO customers(name,email,phone,card_number) VALUES(?,?,?,?)", [
              ("Asha Rao","asha.rao@example.com","+91 98765 43210","4111111111111111"),
              ("Kiran Das","kiran.das@example.com","+91 91234 56789","5555555555554444")])
        c.commit()

def query_customers(args):
    columns = args.get("columns", ["id", "name", "email"])
    allowed = {"id", "name", "email", "phone", "card_number"}
    if not isinstance(columns, list) or not columns or any(x not in allowed for x in columns):
        raise ValueError("Invalid columns")
    limit = args.get("limit", 10)
    if not isinstance(limit, int) or isinstance(limit, bool) or not 1 <= limit <= 20:
        raise ValueError("Invalid limit")
    sql = "SELECT " + ", ".join('"'+x+'"' for x in columns) + " FROM customers LIMIT ?"
    with sqlite3.connect(DB) as c:
        c.row_factory = sqlite3.Row
        return [dict(r) for r in c.execute(sql, (limit,)).fetchall()]

def weather(args):
    return {"city": str(args.get("city", "Bengaluru"))[:80], "temperature_c": 28,
            "condition": "Partly cloudy", "source": "mock-weather"}
