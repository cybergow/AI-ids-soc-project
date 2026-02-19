import sqlite3
import os

DB_PATH = 'alerts.db'

def calculate_metrics():
    if not os.path.exists(DB_PATH):
        print(f"❌ Error: {DB_PATH} not found. Cannot calculate metrics.")
        return

    try:
        conn = sqlite3.connect(DB_PATH)
        cur = conn.cursor()
        
        # Get all relevant rows
        query = """
        SELECT 
            ground_truth,
            iso_is_attack,
            rf_is_attack,
            gnn_is_attack
        FROM model_comparisons
        WHERE ground_truth IS NOT NULL
        """
        cur.execute(query)
        rows = cur.fetchall()
        conn.close()

        if not rows:
            print("⚠️  No labeled data found in 'model_comparisons' table.")
            print("   (ground_truth column is NULL for all rows or table is empty)")
            return

        total_samples = len(rows)
        # Unpack rows into a more usable format
        # row: (ground_truth, iso, rf, gnn)
        attacks = [r for r in rows if r[0] == 1]
        benign = [r for r in rows if r[0] == 0]
        
        print(f"\n📊 DATASET SUMMARY")
        print(f"   Total Samples: {total_samples}")
        print(f"   Attacks:       {len(attacks)} ({(len(attacks)/total_samples)*100:.1f}%)")
        print(f"   Benign:        {len(benign)} ({(len(benign)/total_samples)*100:.1f}%)")
        
        models = {
            'Random Forest': 2,    # Index in the row tuple
            'Isolation Forest': 1,
            'GNN': 3
        }

        print(f"\n📈 REAL PERFORMANCE METRICS (Calculated from {DB_PATH})")
        print(f"{'Model':<20} | {'TPR (Recall)':<12} | {'FPR':<12} | {'Accuracy':<12}")
        print("-" * 65)

        for name, idx in models.items():
            # True Positives: Truth=1 AND Pred=1
            tp = sum(1 for r in rows if r[0] == 1 and r[idx])
            
            # False Positives: Truth=0 and Pred=1
            fp = sum(1 for r in rows if r[0] == 0 and r[idx])
            
            # True Negatives: Truth=0 and Pred=0
            tn = sum(1 for r in rows if r[0] == 0 and not r[idx])
            
            # False Negatives: Truth=1 and Pred=0
            fn = sum(1 for r in rows if r[0] == 1 and not r[idx])
            
            # Calculate Rates
            tpr_denom = tp + fn
            tpr = tp / tpr_denom if tpr_denom > 0 else 0.0
            
            fpr_denom = fp + tn
            fpr = fp / fpr_denom if fpr_denom > 0 else 0.0
            
            acc = (tp + tn) / total_samples if total_samples > 0 else 0.0
            
            # Convert bool/int to 0/1 for correctness in sum if needed (Python treats True as 1)
            
            print(f"{name:<20} | {tpr*100:6.1f}%      | {fpr*100:6.1f}%      | {acc*100:6.1f}%")

        print("\n📝 ACTION: Update your 'research_paper.md' with these values if they differ.")
        print("   If values are 0% or NaN, you need to run more tests with real traffic.")

    except Exception as e:
        print(f"❌ Error reading database: {e}")

if __name__ == "__main__":
    calculate_metrics()
