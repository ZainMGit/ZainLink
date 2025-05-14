import sqlite3

conn = sqlite3.connect("zainlink.db")
cur = conn.cursor()

cur.execute("SELECT id, short, original FROM urls")
rows = cur.fetchall()

print("ID\tShort\t\tOriginal URL")
print("-" * 50)
for row in rows:
    print(f"{row[0]}\t{row[1]}\t{row[2]}")

conn.close()
