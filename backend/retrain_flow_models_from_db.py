import argparse
import json
import os
import sqlite3

import joblib
import numpy as np
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler


def _safe_float(val, default=0.0):
    try:
        if val is None:
            return default
        return float(val)
    except Exception:
        return default


def _extract_features(raw_obj):
    feat = raw_obj.get("features") if isinstance(raw_obj, dict) else None
    if not isinstance(feat, dict):
        feat = raw_obj if isinstance(raw_obj, dict) else {}

    duration = _safe_float(feat.get("duration"))
    pkt_count = _safe_float(feat.get("pkt_count"))
    byte_count = _safe_float(feat.get("byte_count"))

    mean_pkt = feat.get("mean_pkt_size")
    if mean_pkt is None:
        mean_pkt = (byte_count / pkt_count) if pkt_count else 0.0
    mean_pkt = _safe_float(mean_pkt)

    src2dst = _safe_float(feat.get("src2dst_pkts"))
    dst2src = _safe_float(feat.get("dst2src_pkts"))

    return {
        "duration": duration,
        "pkt_count": pkt_count,
        "byte_count": byte_count,
        "src2dst_pkts": src2dst,
        "dst2src_pkts": dst2src,
        "mean_pkt_size": mean_pkt,
    }


def _choose_rf_threshold(y_true, scores):
    scores = np.asarray(scores, dtype=float)
    y_true = np.asarray(y_true, dtype=int)

    uniq = np.unique(scores)
    if len(uniq) > 2000:
        uniq = np.quantile(scores, np.linspace(0, 1, 2000))

    best = (0.0, 1.0, 0.5)
    for t in uniq:
        pred = (scores >= t).astype(int)
        tp = int(((pred == 1) & (y_true == 1)).sum())
        fp = int(((pred == 1) & (y_true == 0)).sum())
        tn = int(((pred == 0) & (y_true == 0)).sum())
        fn = int(((pred == 0) & (y_true == 1)).sum())

        prec = tp / (tp + fp) if (tp + fp) else 0.0
        rec = tp / (tp + fn) if (tp + fn) else 0.0
        f1 = (2 * prec * rec / (prec + rec)) if (prec + rec) else 0.0
        fpr = fp / (fp + tn) if (fp + tn) else 0.0

        cand = (f1, -fpr, float(t))
        if cand > best:
            best = cand

    return float(best[2])


def _choose_iso_threshold(iso_scores_benign, quantile=0.99):
    values = np.asarray(iso_scores_benign, dtype=float)
    if values.size == 0:
        return 0.85
    return float(np.quantile(values, quantile))


def _choose_score_threshold(y_true, scores, max_fpr=None):
    scores = np.asarray(scores, dtype=float)
    y_true = np.asarray(y_true, dtype=int)

    uniq = np.unique(scores)
    if len(uniq) > 2000:
        uniq = np.quantile(scores, np.linspace(0, 1, 2000))

    best = (0.0, 0.0, 0.0, float(uniq[0]) if len(uniq) else 0.5)  # (f1, tpr, -fpr, t)
    for t in uniq:
        pred = (scores >= t).astype(int)
        tp = int(((pred == 1) & (y_true == 1)).sum())
        fp = int(((pred == 1) & (y_true == 0)).sum())
        tn = int(((pred == 0) & (y_true == 0)).sum())
        fn = int(((pred == 0) & (y_true == 1)).sum())

        prec = tp / (tp + fp) if (tp + fp) else 0.0
        rec = tp / (tp + fn) if (tp + fn) else 0.0
        f1 = (2 * prec * rec / (prec + rec)) if (prec + rec) else 0.0
        fpr = fp / (fp + tn) if (fp + tn) else 0.0
        tpr = rec

        if max_fpr is not None and fpr > float(max_fpr):
            continue

        cand = (float(f1), float(tpr), float(-fpr), float(t))
        if cand > best:
            best = cand

    return float(best[3]), float(best[1]), float(-best[2])


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--db", default="alerts.db")
    parser.add_argument("--sources", default="payload")
    parser.add_argument("--attack-limit", type=int, default=0)
    parser.add_argument("--benign-limit", type=int, default=0)
    parser.add_argument("--gnn-max-fpr", type=float, default=0.05)
    args = parser.parse_args()

    sources = [s.strip() for s in (args.sources or "").split(",") if s.strip()]
    if not sources:
        sources = ["payload"]

    conn = sqlite3.connect(args.db)
    cur = conn.cursor()

    placeholders = ",".join(["?"] * len(sources))
    where = f"ground_truth IS NOT NULL AND label_source IN ({placeholders})"

    cur.execute(f"SELECT COUNT(*) FROM model_comparisons WHERE {where} AND ground_truth=1", tuple(sources))
    attack_total = int(cur.fetchone()[0] or 0)
    cur.execute(f"SELECT COUNT(*) FROM model_comparisons WHERE {where} AND ground_truth=0", tuple(sources))
    benign_total = int(cur.fetchone()[0] or 0)

    cur.execute(
        f"SELECT gnn_score, ground_truth FROM model_comparisons WHERE {where} AND gnn_score IS NOT NULL",
        tuple(sources),
    )
    gnn_rows = cur.fetchall()

    if attack_total < 10 or benign_total < 10:
        raise SystemExit(f"Not enough labeled samples for training. attacks={attack_total} benign={benign_total} sources={sources}")

    attack_limit = args.attack_limit or attack_total
    benign_limit = args.benign_limit or min(benign_total, max(attack_limit * 5, 500))

    cur.execute(
        f"SELECT raw_json FROM model_comparisons WHERE {where} AND ground_truth=1 AND raw_json IS NOT NULL ORDER BY RANDOM() LIMIT ?",
        tuple(sources) + (attack_limit,),
    )
    attack_rows = [r[0] for r in cur.fetchall()]

    cur.execute(
        f"SELECT raw_json FROM model_comparisons WHERE {where} AND ground_truth=0 AND raw_json IS NOT NULL ORDER BY RANDOM() LIMIT ?",
        tuple(sources) + (benign_limit,),
    )
    benign_rows = [r[0] for r in cur.fetchall()]

    conn.close()

    X = []
    y = []
    for raw in benign_rows:
        try:
            obj = json.loads(raw)
        except Exception:
            continue
        f = _extract_features(obj)
        X.append([f[k] for k in ("duration", "pkt_count", "byte_count", "src2dst_pkts", "dst2src_pkts", "mean_pkt_size")])
        y.append(0)

    for raw in attack_rows:
        try:
            obj = json.loads(raw)
        except Exception:
            continue
        f = _extract_features(obj)
        X.append([f[k] for k in ("duration", "pkt_count", "byte_count", "src2dst_pkts", "dst2src_pkts", "mean_pkt_size")])
        y.append(1)

    X = np.asarray(X, dtype=float)
    y = np.asarray(y, dtype=int)

    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    benign_scaled = X_scaled[y == 0]
    attack_ratio = float((y == 1).mean())
    contamination = float(min(0.15, max(0.01, attack_ratio)))

    iso_model = IsolationForest(
        contamination=contamination,
        random_state=42,
        n_estimators=300,
        n_jobs=-1,
    )
    iso_model.fit(benign_scaled)

    X_train, X_test, y_train, y_test = train_test_split(
        X_scaled, y, test_size=0.25, stratify=y, random_state=42
    )

    rf_model = RandomForestClassifier(
        n_estimators=400,
        max_depth=12,
        random_state=42,
        class_weight="balanced",
    )
    rf_model.fit(X_train, y_train)

    rf_probs = rf_model.predict_proba(X_test)
    attack_idx = 1
    try:
        matches = np.where(getattr(rf_model, "classes_", np.array([0, 1])) == 1)[0]
        if len(matches):
            attack_idx = int(matches[0])
    except Exception:
        attack_idx = 1

    rf_attack_probs = rf_probs[:, attack_idx]
    rf_threshold = _choose_rf_threshold(y_test, rf_attack_probs)

    decisions = iso_model.decision_function(X_test)
    iso_offset = float(getattr(iso_model, "offset_", -0.5))
    denom = abs(iso_offset) if iso_offset not in (None, 0) else 1.0
    iso_scores = np.clip((-decisions) / denom, 0.0, 1.0)
    iso_threshold = _choose_iso_threshold(iso_scores[y_test == 0], quantile=0.99)

    joblib.dump(iso_model, "flow_isoforest_model.pkl")
    joblib.dump(rf_model, "flow_random_forest_model.pkl")
    joblib.dump(scaler, "flow_model_scaler.pkl")

    config = {
        "features": [
            "duration",
            "pkt_count",
            "byte_count",
            "src2dst_pkts",
            "dst2src_pkts",
            "mean_pkt_size",
        ],
        "rf_threshold": rf_threshold,
        "iso_contamination": contamination,
        "iso_score_threshold": iso_threshold,
        "iso_offset": iso_offset,
    }
    with open("flow_model_config.json", "w", encoding="utf-8") as f:
        json.dump(config, f, indent=2)

    gnn_threshold = None
    gnn_tpr = None
    gnn_fpr = None
    try:
        if gnn_rows:
            gnn_scores = np.asarray([float(r[0]) for r in gnn_rows], dtype=float)
            gnn_truth = np.asarray([int(r[1]) for r in gnn_rows], dtype=int)
            max_fpr = args.gnn_max_fpr
            if max_fpr is not None and max_fpr <= 0:
                max_fpr = None
            gnn_threshold, gnn_tpr, gnn_fpr = _choose_score_threshold(gnn_truth, gnn_scores, max_fpr=max_fpr)

            project_root = os.path.dirname(os.path.dirname(__file__))
            gnn_cfg_path = os.path.join(project_root, "gnn_flow_config.json")
            existing = {}
            if os.path.exists(gnn_cfg_path):
                try:
                    with open(gnn_cfg_path, "r", encoding="utf-8") as f:
                        existing = json.load(f) or {}
                except Exception:
                    existing = {}
            existing["threshold"] = float(gnn_threshold)
            with open(gnn_cfg_path, "w", encoding="utf-8") as f:
                json.dump(existing, f, indent=2)
    except Exception:
        gnn_threshold = None

    print("Trained from DB")
    print(" sources=", sources)
    print(" attacks=", int((y == 1).sum()), "benign=", int((y == 0).sum()))
    print(" contamination=", contamination)
    print(" rf_threshold=", rf_threshold)
    print(" iso_score_threshold=", iso_threshold)
    if gnn_threshold is not None:
        print(" gnn_threshold=", gnn_threshold, "(tpr=", gnn_tpr, "fpr=", gnn_fpr, ")")


if __name__ == "__main__":
    main()
