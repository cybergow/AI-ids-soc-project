import sqlite3
import pandas as pd
import numpy as np

DB_PATH = 'alerts.db'

def calculate_metrics():
    if not os.path.exists(DB_PATH):
        print(f"❌ Error: {DB_PATH} not found. Cannot calculate metrics.")
        return

    try:
        conn = sqlite3.connect(DB_PATH)
        query = """
        SELECT 
            ground_truth,
            iso_is_attack, iso_score,
            rf_is_attack, rf_score,
            gnn_is_attack, gnn_score
        FROM model_comparisons
        WHERE ground_truth IS NOT NULL
        """
        df = pd.read_sql_query(query, conn)
        conn.close()

        if df.empty:
            print("⚠️  No labeled data found in 'model_comparisons' table.")
            print("   (ground_truth column is NULL for all rows)")
            return

        total_samples = len(df)
        attacks = df[df['ground_truth'] == 1]
        benign = df[df['ground_truth'] == 0]
        
        print(f"\n📊 DATASET SUMMARY")
        print(f"   Total Samples: {total_samples}")
        print(f"   Attacks:       {len(attacks)} ({(len(attacks)/total_samples)*100:.1f}%)")
        print(f"   Benign:        {len(benign)} ({(len(benign)/total_samples)*100:.1f}%)")
        
        models = {
            'Random Forest': 'rf_is_attack',
            'Isolation Forest': 'iso_is_attack',
            'GNN': 'gnn_is_attack'
        }

        print(f"\n📈 REAL PERFORMANCE METRICS (Calculated from {DB_PATH})")
        print(f"{'Model':<20} | {'TPR (Recall)':<12} | {'FPR':<12} | {'Accuracy':<12}")
        print("-" * 65)

        for name, col in models.items():
            # True Positives (TP): Model says Attack (1) AND Truth is Attack (1)
            tp = len(df[(df[col] == 1) & (df['ground_truth'] == 1)])
            
            # False Positives (FP): Model says Attack (1) BUT Truth is Benign (0)
            fp = len(df[(df[col] == 1) & (df['ground_truth'] == 0)])
            
            # True Negatives (TN): Model says Benign (0) AND Truth is Benign (0)
            tn = len(df[(df[col] == 0) & (df['ground_truth'] == 0)])
            
            # False Negatives (FN): Model says Benign (0) BUT Truth is Attack (1)
            fn = len(df[(df[col] == 0) & (df['ground_truth'] == 1)])
            
            # Calculate Rates
            tpr = tp / (tp + fn) if (tp + fn) > 0 else 0.0
            fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
            acc = (tp + tn) / total_samples if total_samples > 0 else 0.0
            
            print(f"{name:<20} | {tpr*100:6.1f}%      | {fpr*100:6.1f}%      | {acc*100:6.1f}%")

        print("\n📝 ACTION: Update your 'research_paper.md' with these values.")

    except Exception as e:
        print(f"❌ Error reading database: {e}")

if __name__ == "__main__":
    import os
    calculate_metrics()
