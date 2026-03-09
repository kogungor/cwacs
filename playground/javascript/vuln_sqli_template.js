function run(db, userId) {
  db.query(`SELECT * FROM users WHERE id=${userId}`);
}

module.exports = { run };
