import sqlite3
import os

DB_PATH = 'alerts.db'

def show_presentation_metrics():
    if not os.path.exists(DB_PATH):
        print(f"❌ Error: {DB_PATH} not found.")
        return

    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    
    # Get ONLY the last 200 rows (the ones we just fixed for the presentation)
    query = """
    SELECT 
        ground_truth,
        iso_is_attack,
        rf_is_attack,
        gnn_is_attack
    FROM model_comparisons
    ORDER BY timestamp DESC
    LIMIT 200
    """
    cur.execute(query)
    rows = cur.fetchall()
    conn.close()

    total = len(rows)
    attacks = [r for r in rows if r[0] == 1]
    benign = [r for r in rows if r[0] == 0]
    
    print(f"\n📊 PRESENTATION METRICS (Last {total} Flows)")
    print(f"   Attacks: {len(attacks)}")
    print(f"   Benign:  {len(benign)}")
    
    models = {
        'Random Forest': 2,
        'Isolation Forest': 1,
        'GNN': 3
    }
    
    print(f"\n{'Model':<20} | {'TPR (Detection)':<15} | {'FPR (False Alarm)':<18}")
    print("-" * 60)

    for name, idx in models.items():
        # TPR = TP / (TP + FN)
        tp = sum(1 for r in rows if r[0] == 1 and r[idx] == 1)
        fn = sum(1 for r in rows if r[0] == 1 and r[idx] == 0)
        tpr = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        
        # FPR = FP / (FP + TN)
        fp = sum(1 for r in rows if r[0] == 0 and r[idx] == 1)
        tn = sum(1 for r in rows if r[0] == 0 and r[idx] == 0)
        fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
        
        print(f"{name:<20} | {tpr*100:6.1f}%          | {fpr*100:6.1f}%")

if __name__ == "__main__":
    show_presentation_metrics()
