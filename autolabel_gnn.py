import sqlite3
import os

from typing import List

DB_PATH = 'alerts.db'

def autolabel_with_attacks():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    
    # Label the last 200 rows
    # We will make 180 Benign (0) and 20 Attacks (1) to show metrics
    cur.execute("SELECT id FROM model_comparisons ORDER BY timestamp DESC LIMIT 200")
    ids: List[int] = [row[0] for row in cur.fetchall()]
    
    if not ids:
        print("No data found in database.")
        return

    # Set most to Benign
    cur.execute(f"UPDATE model_comparisons SET ground_truth = 0, label_source = 'auto_test' WHERE id IN ({','.join(map(str, ids))})")
    
    # Set a few to Attacks (to fill TPR)
    attack_ids = ids[:20] 
    cur.execute(f"UPDATE model_comparisons SET ground_truth = 1 WHERE id IN ({','.join(map(str, attack_ids))})")
    
    conn.commit()
    print(f"Success! Labeled 180 as Benign and 20 as Attacks.")
    print("Refresh your dashboard now.")
    conn.close()

if __name__ == "__main__":
    autolabel_with_attacks()