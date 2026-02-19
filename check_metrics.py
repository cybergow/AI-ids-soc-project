import sqlite3
import os
import json
import logging

# Mock logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Mock some globals from detector_server
MODEL_METRICS_WINDOW = 200
gnn_scorer = None

def _safe_div(num, denom):
    return float(num / denom) if denom else None

def _average(values):
    if not values:
        return None
    return float(sum(values) / len(values))

def _score_consistency(values):
    if len(values) < 2:
        return None
    import numpy as np
    stddev = float(np.std(values))
    return float(max(0.0, min(1.0, 1.0 - stddev)))

def _row_to_dict(row, keys):
    return {key: row[i] for i, key in enumerate(keys)}

def compute_model_metrics_snapshot(cur, current_row=None, window=MODEL_METRICS_WINDOW):
    keys = [
        "ground_truth", "label_source",
        "iso_is_attack", "iso_score",
        "rf_is_attack", "rf_score",
        "gnn_is_attack", "gnn_score",
    ]

    gnn_threshold = 0.95 # Mocking it as per config

    cur.execute(
        """
        SELECT ground_truth, label_source,
               iso_is_attack, iso_score,
               rf_is_attack, rf_score,
               gnn_is_attack, gnn_score
        FROM model_comparisons
        WHERE ground_truth IS NOT NULL
        ORDER BY timestamp DESC
        LIMIT ?
        """,
        (max(1, int(window)),),
    )
    db_rows = cur.fetchall()
    rows = [_row_to_dict(row, keys) for row in db_rows]
    if current_row and current_row.get("ground_truth") is not None:
        rows.insert(0, current_row)
    rows = rows[: int(window)]

    print(f"DEBUG: Found {len(rows)} labeled rows")

    attack_total = sum(1 for row in rows if row.get("ground_truth") == 1)
    benign_total = sum(1 for row in rows if row.get("ground_truth") == 0)

    model_specs = {
        "isolation_forest": ("iso_is_attack", "iso_score"),
        "random_forest": ("rf_is_attack", "rf_score"),
        "gnn": ("gnn_is_attack", "gnn_score"),
    }
    metrics = {}

    for model_name, (pred_key, score_key) in model_specs.items():
        tp = fp = tn = fn = 0
        scores = []
        flagged_scores = []
        sample_count = 0

        for row in rows:
            truth = row.get("ground_truth")
            pred_val = row.get(pred_key)
            sample_count += 1
            score = row.get(score_key)

            if model_name == "gnn" and gnn_threshold is not None:
                if truth is None or score is None:
                    sample_count -= 1
                    continue
                try:
                    pred = bool(float(score) >= float(gnn_threshold))
                except Exception:
                    sample_count -= 1
                    continue
            else:
                if truth is None or pred_val is None:
                    sample_count -= 1
                    continue
                pred = bool(pred_val)

            if truth == 1 and pred:
                tp += 1
            elif truth == 1 and not pred:
                fn += 1
            elif truth == 0 and pred:
                fp += 1
            elif truth == 0 and not pred:
                tn += 1

            if score is not None:
                score_val = float(score)
                scores.append(score_val)
                if pred:
                    flagged_scores.append(score_val)

        metrics[model_name] = {
            "tpr": _safe_div(tp, tp + fn),
            "fpr": _safe_div(fp, fp + tn),
            "samples": sample_count,
            "tp": tp, "fp": fp, "tn": tn, "fn": fn
        }

    return metrics

db_path = 'alerts.db'
if os.path.exists(db_path):
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    m = compute_model_metrics_snapshot(cur)
    print(json.dumps(m, indent=2))
else:
    print("DB not found in root")
