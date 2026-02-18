import sqlite3
import os

DB_PATH = 'alerts.db'

def show_presentation_metrics():
    if not os.path.exists(DB_PATH):
        with open('final_results_table.txt', 'w') as f:
            f.write(f"❌ Error: {DB_PATH} not found.")
        return

    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    
    query = """
    SELECT ground_truth, iso_is_attack, rf_is_attack, gnn_is_attack
    FROM model_comparisons
    ORDER BY timestamp DESC
    LIMIT 200
    """
    cur.execute(query)
    rows = cur.fetchall()
    conn.close()

    total = len(rows)
    # Filter for attacks/benign from the simulated run
    attack_count = sum(1 for r in rows if r[0] == 1)
    benign_count = sum(1 for r in rows if r[0] == 0)
    
    output = []
    output.append(f"📊 PRESENTATION METRICS (Last {total} Flows)")
    output.append(f"   Attacks: {attack_count} | Benign: {benign_count}")
    output.append("")
    output.append(f"{'Model':<20} | {'TPR (Recall)':<15} | {'FPR':<15}")
    output.append("-" * 60)

    models = {'Random Forest': 2, 'Isolation Forest': 1, 'GNN': 3}
    
    for name, idx in models.items():
        tp = sum(1 for r in rows if r[0] == 1 and r[idx] == 1)
        fp = sum(1 for r in rows if r[0] == 0 and r[idx] == 1)
        tn = sum(1 for r in rows if r[0] == 0 and r[idx] == 0)
        fn = sum(1 for r in rows if r[0] == 1 and r[idx] == 0)
        
        tpr = (tp / (tp + fn)) * 100 if (tp + fn) > 0 else 0.0
        fpr = (fp / (fp + tn)) * 100 if (fp + tn) > 0 else 0.0
        
        output.append(f"{name:<20} | {tpr:5.1f}%          | {fpr:5.1f}%")

    with open('final_results_table.txt', 'w', encoding='utf-8') as f:
        f.write('\n'.join(output))

if __name__ == "__main__":
    show_presentation_metrics()
