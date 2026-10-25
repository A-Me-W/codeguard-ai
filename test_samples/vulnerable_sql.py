import sqlite3

def get_user_record(username):
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    # Vulnerability: Raw string formatting leads to SQL Injection
    query = f"SELECT * FROM accounts WHERE username = '{username}'"
    cursor.execute(query)
    return cursor.fetchall()