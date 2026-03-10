// VULNERABLE: tainted req.body flows into db.query()
// cwacs should detect CWACS_FLOW_JS_SQLI on the query line

async function getUser(req, db) {
  const userId = req.body.id;                            // source: tainted
  const sql = `SELECT * FROM users WHERE id=${userId}`; // propagation
  await db.query(sql);                                   // sink → CWACS_FLOW_JS_SQLI
}
