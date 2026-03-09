def run(user_id, cursor):
    cursor.execute("SELECT * FROM users WHERE id=%s", (user_id,))
