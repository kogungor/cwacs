// SAFE: parameterized query — tainted value not interpolated into SQL string
// cwacs should NOT flag this

async function getUser(req, db) {
  const userId = req.body.id;
  await db.query("SELECT * FROM users WHERE id=$1", [userId]); // safe: parameterized
}
