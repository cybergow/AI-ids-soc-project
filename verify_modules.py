
import requests
import sqlite3
import os
import sys

# Force UTF-8 encoding for safety, though removing emojis is also good
try:
    sys.stdout.reconfigure(encoding='utf-8')
except Exception:
    pass

print("--- VERIFICATION START ---")

# 1. Check Module 3 (Server API)
try:
    print("\n[Module 3: Server API Check]")
    r = requests.get("http://localhost:5000/api/cmd-detections", timeout=5)
    if r.status_code == 200:
        data = r.json()
        if isinstance(data, dict) and 'detections' in data:
            detections = data['detections']
        elif isinstance(data, list):
            detections = data
        else:
            detections = []
            
        count = len(detections)
        print(f"[OK] Server is responsive (Status 200)")
        print(f"[OK] Found {count} command detections via API")
        if count > 0:
            print(f"Sample: {detections[0]}")
    else:
        print(f"[FAIL] Server returned status {r.status_code}")
except Exception as e:
    print(f"[FAIL] API Request Failed: {e}")

# 2. Check Module 2 Data in Module 3's DB
try:
    print("\n[Module 2: Database Persistence Check]")
    db_path = "alerts.db"
    if not os.path.exists(db_path):
        print("[FAIL] alerts.db not found!")
    else:
        conn = sqlite3.connect(db_path)
        cur = conn.cursor()
        
        cur.execute("SELECT COUNT(*) FROM cmd_detections")
        cmd_count = cur.fetchone()[0]
        
        cur.execute("SELECT COUNT(*) FROM system_logs WHERE component='FILELESS_SIM'")
        log_count = cur.fetchone()[0]
        
        print(f"[OK] Found {cmd_count} entries in 'cmd_detections' table")
        print(f"[OK] Found {log_count} entries in 'system_logs' from simulator")
        
        conn.close()
except Exception as e:
    print(f"[FAIL] Database Check Failed: {e}")

print("\n--- VERIFICATION END ---")
