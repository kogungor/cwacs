# VULNERABLE: multi-hop reassignment chain — taint propagates through x → y → sink
# cwacs should detect CWACS_FLOW_PY_SQLI on the execute line

import sys
import sqlite3

def search(db):
    raw = sys.argv[1]                            # source: tainted
    term = raw                                   # propagation hop 1
    clause = "WHERE name=" + term               # propagation hop 2
    db.execute("SELECT * FROM items " + clause) # sink → CWACS_FLOW_PY_SQLI
