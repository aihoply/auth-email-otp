import sqlite3

conn = sqlite3.connect('auth.db')
c = conn.cursor()
c.execute('''
CREATE TABLE IF NOT EXISTS users (
    email TEXT PRIMARY KEY,
    otp TEXT,
    timestamp REAL
)
''')

c.execute('''
CREATE TABLE IF NOT EXISTS blacklisted_tokens (
    token TEXT PRIMARY KEY
)
''')
conn.commit()
conn.close()
