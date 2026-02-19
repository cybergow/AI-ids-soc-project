import sqlite3
import os

db_path = 'alerts.db'
if not os.path.exists(db_path):
    print(f"File {db_path} not found")
    exit(1)

conn = sqlite3.connect(db_path)
cur = conn.cursor()

print("--- Tables ---")
cur.execute("SELECT name FROM sqlite_master WHERE type='table';")
for (table,) in cur.fetchall():
    cur.execute(f"SELECT COUNT(*) FROM {table}")
    count = cur.fetchone()[0]
    print(f"{table}: {count} rows")

print("\n--- Recent Model Comparisons ---")
cur.execute("SELECT iso_is_attack, rf_is_attack, gnn_is_attack, ground_truth FROM model_comparisons ORDER BY id DESC LIMIT 5;")
for row in cur.fetchall():
    print(row)
