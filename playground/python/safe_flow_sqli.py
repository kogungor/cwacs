# SAFE: user input is passed as a parameterized argument — not tainted in query string
# cwacs should NOT flag this

from flask import request
import sqlite3

def get_user(db):
    user_id = request.args.get("id")
    db.execute("SELECT * FROM users WHERE id=%s", (user_id,))  # safe: parameterized
