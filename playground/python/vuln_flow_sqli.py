# VULNERABLE: tainted user input flows into SQL execute()
# cwacs should detect CWACS_FLOW_PY_SQLI on the execute line

from flask import request
import sqlite3

def get_user(db):
    user_id = request.args.get("id")          # source: tainted
    query = "SELECT * FROM users WHERE id=" + user_id  # propagation
    db.execute(query)                          # sink → CWACS_FLOW_PY_SQLI
