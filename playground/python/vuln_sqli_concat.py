def run(user_id, cursor):
    cursor.execute("SELECT * FROM users WHERE id=" + user_id)
