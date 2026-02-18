"""
COMPLETE INTEGRATED IDS-SOC DETECTOR SERVER
Detection Engine + API Server + Real-time Dashboard
Combines: Network Flow Analysis + Command Detection + System Monitoring
Author: AI-IDS SOC Team
Date: January 29, 2026
Status: Production Ready
Location: Root directory of AI-ids-soc-project
"""

# STARTUP FIX FOR PYTHON 3.14+ IMPORTLIB ISSUES
import decimal
try:
    decimal.getcontext().prec = 28
except Exception:
    pass

import socket
import json
import threading
import sqlite3
import time
import os
import logging
import math
from collections import defaultdict, deque
from datetime import datetime
from flask import Flask, send_from_directory, jsonify, request
from flask_socketio import SocketIO
from flask_cors import CORS

# Robust import for numpy/pandas to prevent crashes
try:
    import numpy as np
except ImportError:
    print("WARNING: Numpy not found. Using mock implementation.")
    class MockNumpy:
        def mean(self, x): return sum(x)/len(x) if x else 0
        def std(self, x): return 0
    np = MockNumpy()
except Exception as e:
    print(f"CRITICAL: Error importing numpy: {e}")
    np = None

from system_monitor import SystemCommandMonitor

try:
    from scapy.all import get_if_list
    SCAPY_AVAILABLE = True
except Exception:
    SCAPY_AVAILABLE = False

try:
    from flow_extractor import start_capture as start_flow_capture
    FLOW_EXTRACTOR_AVAILABLE = True
except Exception:
    FLOW_EXTRACTOR_AVAILABLE = False

# ✅ IMPORT HYBRID DETECTOR (Regex + AI)
try:
    from cmd_detector_hybrid import HybridCMDDetector
    HYBRID_AVAILABLE = True
except ImportError:
    HYBRID_AVAILABLE = False

# ✅ OPTIONALLY IMPORT TRAINER (for on-demand model retraining)
try:
    from cmd_ai_trainer import CMDDetectorAIModel
    AI_TRAINER_AVAILABLE = True
except ImportError:
    AI_TRAINER_AVAILABLE = False

# ✅ OPTIONAL GNN FLOW SCORER
GNN_AVAILABLE = False
try:
    from gnn_flow_model import GNNFlowScorer
    GNN_AVAILABLE = True
except (ImportError, Exception) as e:
    # Use a print here because logging isn't fully configured yet
    print(f"DEBUG: GNN import failed (this is okay): {e}")
    GNN_AVAILABLE = False

# ✅ OPTIONAL FLOW MODEL ENSEMBLE
ENSEMBLE_AVAILABLE = False
try:
    from flow_model_ensemble import FlowModelEnsemble
    ENSEMBLE_AVAILABLE = True
except (ImportError, Exception) as e:
    print(f"DEBUG: Flow Ensemble import failed (this is okay): {e}")
    ENSEMBLE_AVAILABLE = False

# ============================================================================
# LOGGING CONFIGURATION
# ============================================================================

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

logger.info("=" * 80)
logger.info("🚀 IDS DETECTOR SERVER - INITIALIZING (Network + System + CMD + AI)")
logger.info("=" * 80)

# ============================================================================
# PATHS & CONFIGURATION
# ============================================================================

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.abspath(os.path.join(BASE_DIR, ".."))
DB_PATH = os.path.join(PROJECT_ROOT, "alerts.db")

# Ensure we look for models in the project root
ISO_MODEL_PATH = os.path.join(PROJECT_ROOT, "flow_isoforest_model.pkl")
RF_MODEL_PATH = os.path.join(PROJECT_ROOT, "flow_random_forest_model.pkl")
SCALER_PATH = os.path.join(PROJECT_ROOT, "flow_model_scaler.pkl")
CONFIG_PATH = os.path.join(PROJECT_ROOT, "flow_model_config.json")

MODEL_METRICS_WINDOW = int(os.environ.get("MODEL_METRICS_WINDOW", "200"))

# ============================================================================
# GLOBAL STATE & MODEL INITIALIZATION
# ============================================================================

ml_mode = "none"
scaler = None
model = None

gnn_scorer = None
if GNN_AVAILABLE:
    try:
        gnn_scorer = GNNFlowScorer()
        if gnn_scorer.is_ready:
            logger.info("✅ GNN flow scorer loaded")
        else:
            logger.warning("⚠️  GNN flow scorer not ready (model/config missing)")
    except Exception as e:
        logger.warning(f"⚠️  GNN flow scorer failed to initialize: {e}")

flow_ensemble = None
if ENSEMBLE_AVAILABLE:
    try:
        # Pass absolute paths to ensure models are found regardless of CWD
        flow_ensemble = FlowModelEnsemble(
            iso_model_path=ISO_MODEL_PATH,
            rf_model_path=RF_MODEL_PATH,
            scaler_path=SCALER_PATH,
            config_path=CONFIG_PATH
        )
        if flow_ensemble.is_ready:
            logger.info("✅ Flow model ensemble loaded (Isolation Forest + Random Forest + GNN)")
            logger.info(f"   - Isolation Forest: {'Online' if flow_ensemble.has_isolation_forest else 'Offline'}")
            logger.info(f"   - Random Forest: {'Online' if flow_ensemble.has_random_forest else 'Offline'}")
            logger.info(f"   - GNN: {'Online' if flow_ensemble.has_gnn else 'Offline'}")
        else:
            logger.warning("⚠️  Flow model ensemble not ready (models or scaler missing)")
            logger.warning(f"   Searching in: {PROJECT_ROOT}")
    except Exception as e:
        logger.warning(f"⚠️  Flow model ensemble failed to initialize: {e}")

# Initialize Hybrid CMD Detector (Regex + AI)
cmd_detector = None
if HYBRID_AVAILABLE:
    try:
        cmd_detector = HybridCMDDetector(use_ai=True)
        logger.info(f"✅ Hybrid CMD Detector loaded")
        logger.info(f"   - Regex patterns: 47")
        logger.info(f"   - AI model: {'✅ Available' if cmd_detector.ai_detector.is_loaded else '⚠️  Not available (will use regex only)'}")
    except Exception as e:
        logger.error(f"❌ Failed to load hybrid detector: {e}")
        cmd_detector = None
else:
    logger.warning("⚠️  cmd_detector_hybrid.py not found - will use regex-only mode")

# ============================================================================
# FLASK & SOCKETIO SETUP
# ============================================================================

app = Flask(__name__, static_folder="../frontend", static_url_path="/")
CORS(app)
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')

logger.info(" Flask app initialized with CORS enabled")

MODEL_METRICS_WINDOW = int(os.environ.get("MODEL_METRICS_WINDOW", "200"))

TRUTHY_LABELS = {"attack", "malicious", "anomaly", "true", "yes", "1"}
FALSY_LABELS = {"benign", "normal", "false", "no", "0"}


def _parse_truth_value(value):
    if value is None:
        return None
    if isinstance(value, bool):
        return 1 if value else 0
    if isinstance(value, (int, float)):
        if isinstance(value, float) and math.isnan(value):
            return None
        return 1 if value > 0 else 0
    if isinstance(value, str):
        text = value.strip().lower()
        if text in TRUTHY_LABELS:
            return 1
        if text in FALSY_LABELS:
            return 0
    return None


def _extract_ground_truth(feat, incoming_is_anomaly, incoming_severity, fallback_is_attack):
    label_keys = ("ground_truth", "label", "truth", "attack_label", "is_attack_truth")
    for key in label_keys:
        if key in feat:
            parsed = _parse_truth_value(feat.get(key))
            if parsed is not None:
                return parsed, "payload"

    parsed = _parse_truth_value(incoming_is_anomaly)
    if parsed is not None:
        return parsed, "payload"

    if incoming_severity:
        severity = str(incoming_severity).strip().lower()
        if severity in ("critical", "high"):
            return 1, "payload"
        if severity in ("medium", "low", "normal", "benign"):
            return 0, "payload"

    if fallback_is_attack is None:
        return None, "unknown"
    return (1 if fallback_is_attack else 0), "system"


def _safe_div(num, denom):
    return float(num / denom) if denom else None


def _average(values):
    if not values:
        return None
    return float(np.mean(values))


def _score_consistency(values):
    if len(values) < 2:
        return None
    stddev = float(np.std(values))
    return float(max(0.0, min(1.0, 1.0 - stddev)))


def _row_to_dict(row, keys):
    if isinstance(row, sqlite3.Row):
        return {key: row[key] for key in keys}
    return dict(zip(keys, row))


def compute_model_metrics_snapshot(cur, current_row=None, window=MODEL_METRICS_WINDOW):
    keys = [
        "ground_truth", "label_source",
        "iso_is_attack", "iso_score",
        "rf_is_attack", "rf_score",
        "gnn_is_attack", "gnn_score",
    ]

    gnn_threshold = None
    try:
        if gnn_scorer is not None and getattr(gnn_scorer, "is_ready", False):
            gnn_threshold = float(getattr(gnn_scorer, "threshold", 0.0) or 0.5)
    except Exception:
        gnn_threshold = None
    if gnn_threshold is None:
        try:
            project_root = os.path.dirname(os.path.dirname(__file__))
            cfg_path = os.path.join(project_root, "gnn_flow_config.json")
            if os.path.exists(cfg_path):
                with open(cfg_path, "r", encoding="utf-8") as f:
                    cfg = json.load(f)
                if cfg.get("threshold") is not None:
                    try:
                        gnn_threshold = float(cfg.get("threshold") or 0.0)
                    except ValueError:
                        gnn_threshold = 0.5
        except Exception:
            gnn_threshold = None

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
    rows = [_row_to_dict(row, keys) for row in cur.fetchall()]
    if current_row and current_row.get("ground_truth") is not None:
        rows.insert(0, current_row)
    rows = rows[: int(window)]

    label_sources = defaultdict(int)
    for row in rows:
        label_sources[(row.get("label_source") or "unknown")] += 1

    attack_total = sum(1 for row in rows if row.get("ground_truth") == 1)
    benign_total = sum(1 for row in rows if row.get("ground_truth") == 0)

    model_specs = {
        "isolation_forest": ("iso_is_attack", "iso_score"),
        "random_forest": ("rf_is_attack", "rf_score"),
        "gnn": ("gnn_is_attack", "gnn_score"),
    }
    
    # Check model availability for more accurate status reporting
    model_readiness = {
        "isolation_forest": bool(flow_ensemble and flow_ensemble.has_isolation_forest),
        "random_forest": bool(flow_ensemble and flow_ensemble.has_random_forest),
        "gnn": bool(flow_ensemble and flow_ensemble.has_gnn) if flow_ensemble else bool(gnn_scorer and gnn_scorer.is_ready),
    }

    metrics = {}

    unique_counts = {name: 0 for name in model_specs}
    for row in rows:
        if row.get("ground_truth") != 1:
            continue
        preds = {}
        for model_name, (pred_key, _) in model_specs.items():
            if model_name == "gnn" and gnn_threshold is not None:
                try:
                    gnn_score = row.get("gnn_score")
                    preds[model_name] = bool(gnn_score is not None and float(gnn_score or 0.0) >= float(gnn_threshold or 0.0)) # SAFE_FLOAT
                except Exception:
                    preds[model_name] = False
            else:
                pred_val = row.get(pred_key)
                preds[model_name] = bool(pred_val) if pred_val is not None else False
        if sum(1 for val in preds.values() if val) == 1:
            for model_name, pred_val in preds.items():
                if pred_val:
                    unique_counts[model_name] += 1

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
                    pred = bool(float(score or 0.0) >= float(gnn_threshold or 0.0))
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
            "confidence": _average(flagged_scores),
            "consistency": _score_consistency(scores),
            "unique_rate": _safe_div(unique_counts[model_name], attack_total),
            "samples": sample_count,
            "status": "ready" if model_readiness.get(model_name) else "not_ready",
            "tp": tp,
            "fp": fp,
            "tn": tn,
            "fn": fn,
        }

    return {
        "window": int(window),
        "samples_total": len(rows),
        "samples_attacks": attack_total,
        "samples_benign": benign_total,
        "label_sources": dict(label_sources),
        "gnn_threshold_used": gnn_threshold,
        "models": metrics,
    }

system_monitor = None
if cmd_detector:
    system_monitor = SystemCommandMonitor(detector=cmd_detector, socketio=socketio)
    logger.info(" System command monitor initialized")
else:
    logger.warning("  System command monitor not initialized: cmd_detector is not available.")

# ============================================================================
# DATABASE INITIALIZATION
# ============================================================================

def init_db():
    """Initialize SQLite database for alert storage"""
    try:
        conn = sqlite3.connect(DB_PATH, check_same_thread=False, timeout=30)
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()

        try:
            cur.execute("PRAGMA journal_mode=WAL")
            cur.execute("PRAGMA synchronous=NORMAL")
            cur.execute("PRAGMA busy_timeout=5000")
        except Exception:
            pass
        
        # Network alerts table
        cur.execute('''
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp REAL,
                src_ip TEXT,
                dst_ip TEXT,
                src_port INTEGER,
                dst_port INTEGER,
                proto INTEGER,
                score REAL,
                is_anomaly INTEGER,
                pkt_count INTEGER,
                byte_count INTEGER,
                duration REAL,
                mean_pkt_size REAL,
                reason TEXT,
                severity TEXT,
                raw_json TEXT
            )
        ''')

        cur.execute('''
            CREATE TABLE IF NOT EXISTS network_flows (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp REAL,
                src_ip TEXT,
                dst_ip TEXT,
                src_port INTEGER,
                dst_port INTEGER,
                proto INTEGER,
                score REAL,
                is_anomaly INTEGER,
                pkt_count INTEGER,
                byte_count INTEGER,
                duration REAL,
                mean_pkt_size REAL,
                raw_json TEXT
            )
        ''')
        
        # CMD detection table (stores both regex and AI detections)
        cur.execute('''
            CREATE TABLE IF NOT EXISTS cmd_detections (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp REAL,
                command TEXT,
                severity TEXT,
                confidence REAL,
                reason TEXT,
                matched_pattern TEXT,
                detection_method TEXT,
                regex_matched BOOLEAN,
                ai_score REAL
            )
        ''')

        try:
            cur.execute("PRAGMA table_info(cmd_detections)")
            existing_cols = {row[1] for row in cur.fetchall()}
            if 'is_malicious' not in existing_cols:
                cur.execute("ALTER TABLE cmd_detections ADD COLUMN is_malicious BOOLEAN DEFAULT 0")
        except Exception as e:
            logger.error(f"Database migration failed (cmd_detections): {e}")
        
        # AI training history table
        cur.execute('''
            CREATE TABLE IF NOT EXISTS ai_training_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp REAL,
                model_type TEXT,
                accuracy REAL,
                precision REAL,
                recall REAL,
                f1_score REAL,
                status TEXT
            )
        ''')
        
        # System logs table
        cur.execute('''
            CREATE TABLE IF NOT EXISTS system_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp REAL,
                level TEXT,
                component TEXT,
                message TEXT,
                source TEXT
            )
        ''')
        
        # Model comparisons table
        cur.execute('''
            CREATE TABLE IF NOT EXISTS model_comparisons (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp REAL,
                src_ip TEXT,
                dst_ip TEXT,
                src_port INTEGER,
                dst_port INTEGER,
                proto INTEGER,
                ground_truth INTEGER,
                label_source TEXT,
                ensemble_score REAL,
                ensemble_is_attack INTEGER,
                ensemble_reason TEXT,
                iso_score REAL,
                iso_is_attack INTEGER,
                iso_reason TEXT,
                iso_tpr REAL,
                iso_fpr REAL,
                iso_confidence REAL,
                iso_consistency REAL,
                iso_unique_rate REAL,
                iso_tp INTEGER,
                iso_fp INTEGER,
                iso_tn INTEGER,
                iso_fn INTEGER,
                iso_samples INTEGER,
                rf_score REAL,
                rf_is_attack INTEGER,
                rf_reason TEXT,
                rf_tpr REAL,
                rf_fpr REAL,
                rf_confidence REAL,
                rf_consistency REAL,
                rf_unique_rate REAL,
                rf_tp INTEGER,
                rf_fp INTEGER,
                rf_tn INTEGER,
                rf_fn INTEGER,
                rf_samples INTEGER,
                gnn_score REAL,
                gnn_is_attack INTEGER,
                gnn_reason TEXT,
                gnn_tpr REAL,
                gnn_fpr REAL,
                gnn_confidence REAL,
                gnn_consistency REAL,
                gnn_unique_rate REAL,
                gnn_tp INTEGER,
                gnn_fp INTEGER,
                gnn_tn INTEGER,
                gnn_fn INTEGER,
                gnn_samples INTEGER,
                raw_json TEXT
            )
        ''')

        try:
            cur.execute("PRAGMA table_info(model_comparisons)")
            existing_cols = {row[1] for row in cur.fetchall()}
            new_cols = {
                "ground_truth": "INTEGER",
                "label_source": "TEXT",
                "iso_tpr": "REAL",
                "iso_fpr": "REAL",
                "iso_confidence": "REAL",
                "iso_consistency": "REAL",
                "iso_unique_rate": "REAL",
                "iso_tp": "INTEGER",
                "iso_fp": "INTEGER",
                "iso_tn": "INTEGER",
                "iso_fn": "INTEGER",
                "iso_samples": "INTEGER",
                "rf_tpr": "REAL",
                "rf_fpr": "REAL",
                "rf_confidence": "REAL",
                "rf_consistency": "REAL",
                "rf_unique_rate": "REAL",
                "rf_tp": "INTEGER",
                "rf_fp": "INTEGER",
                "rf_tn": "INTEGER",
                "rf_fn": "INTEGER",
                "rf_samples": "INTEGER",
                "gnn_tpr": "REAL",
                "gnn_fpr": "REAL",
                "gnn_confidence": "REAL",
                "gnn_consistency": "REAL",
                "gnn_unique_rate": "REAL",
                "gnn_tp": "INTEGER",
                "gnn_fp": "INTEGER",
                "gnn_tn": "INTEGER",
                "gnn_fn": "INTEGER",
                "gnn_samples": "INTEGER",
            }
            for col, col_type in new_cols.items():
                if col not in existing_cols:
                    cur.execute(f"ALTER TABLE model_comparisons ADD COLUMN {col} {col_type}")
        except Exception as e:
            logger.error(f"Database migration failed (model_comparisons): {e}")
        
        # Create indexes
        cur.execute('''
            CREATE INDEX IF NOT EXISTS idx_timestamp ON alerts(timestamp DESC)
        ''')

        cur.execute('''
            CREATE INDEX IF NOT EXISTS idx_flow_timestamp ON network_flows(timestamp DESC)
        ''')
        
        cur.execute('''
            CREATE INDEX IF NOT EXISTS idx_model_comparisons_timestamp ON model_comparisons(timestamp DESC)
        ''')
        
        cur.execute('''
            CREATE INDEX IF NOT EXISTS idx_severity ON alerts(severity)
        ''')
        
        cur.execute('''
            CREATE INDEX IF NOT EXISTS idx_cmd_timestamp ON cmd_detections(timestamp DESC)
        ''')
        
        cur.execute('''
            CREATE INDEX IF NOT EXISTS idx_logs_timestamp ON system_logs(timestamp DESC)
        ''')
        
        conn.commit()
        logger.info(f"Database initialized: {DB_PATH}")
        return conn
    except Exception as e:
        logger.error(f"Database initialization failed: {e}")
        raise

db_conn = init_db()

network_runtime = {
    'udp_flows_received': 0,
    'last_udp_flow_ts': 0.0,
    'flow_extractor_started': False,
    'flow_extractor_iface': None,
    'flow_extractor_udp': "",
    'flow_extractor_error': None,
    'flow_extractor_start_ts': 0.0
}

def choose_default_flow_iface():
    if os.name != 'nt':
        return None
    try:
        from scapy.arch.windows import get_windows_if_list
        ifaces = get_windows_if_list() or []

        def _has_real_ip(ips):
            ips = ips or []
            for ip in ips:
                if not ip:
                    continue
                ip_s = str(ip)
                if '.' in ip_s:
                    if ip_s.startswith(('169.254.', '127.')):
                        continue
                    return True
                if ':' in ip_s:
                    low = ip_s.lower()
                    if low.startswith('fe80') or ip_s == '::1':
                        continue
                    return True
            return False

        def _is_bad_iface(desc):
            desc = (desc or '').lower()
            bad = (
                'loopback',
                'virtualbox',
                'vmware',
                'wi-fi direct',
                'bluetooth',
                'npcap loopback',
                'wfp native',
                'qos packet scheduler'
            )
            return any(b in desc for b in bad)

        candidates = []
        for i in ifaces:
            desc = i.get('description') or ''
            if _is_bad_iface(desc):
                continue
            if not _has_real_ip(i.get('ips') or []):
                continue
            candidates.append(i)

        if not candidates:
            for i in ifaces:
                desc = i.get('description') or ''
                if _is_bad_iface(desc):
                    continue
                candidates.append(i)

        if not candidates:
            return None

        def _metric(i):
            try:
                m = i.get('ipv4_metric')
                if m is None:
                    m = i.get('ipv6_metric')
                return int(m) if m is not None else 9999
            except Exception:
                return 9999

        best = sorted(candidates, key=_metric)[0]
        guid = best.get('guid')
        if guid:
            return f"\\Device\\NPF_{guid}"
        return best.get('name')
    except Exception:
        return None
    return None

def resolve_flow_iface(iface):
    if not iface:
        return None
    try:
        if SCAPY_AVAILABLE:
            try:
                if iface in (get_if_list() or []):
                    return iface
            except Exception:
                pass

        if os.name == 'nt':
            from scapy.arch.windows import get_windows_if_list
            win_ifaces = get_windows_if_list() or []
            req = str(iface).strip().lower()

            for i in win_ifaces:
                name = str(i.get('name') or '').strip().lower()
                desc = str(i.get('description') or '').strip().lower()
                if req in (name, desc):
                    guid = i.get('guid')
                    if guid:
                        return f"\\\\Device\\\\NPF_{guid}"
                    return i.get('name') or iface
    except Exception:
        return iface
    return iface

def start_flow_extractor_background():
    """Start optional flow extractor in background"""
    if not FLOW_EXTRACTOR_AVAILABLE:
        logger.warning(" Flow extractor not available (scapy missing or import failed)")
        return

    enabled = os.environ.get('ENABLE_FLOW_EXTRACTOR', '1').strip() == '1'
    if not enabled:
        logger.info(" Flow extractor disabled. Set ENABLE_FLOW_EXTRACTOR=1 to sniff real traffic.")
        return

    iface = os.environ.get('FLOW_EXTRACTOR_IFACE') or None
    udp_host = os.environ.get('FLOW_EXTRACTOR_UDP_HOST', '127.0.0.1')
    udp_port = int(os.environ.get('FLOW_EXTRACTOR_UDP_PORT', '9999'))
    l3_socket = os.environ.get('FLOW_EXTRACTOR_L3', '1').strip() == '1'

    if not iface:
        iface = choose_default_flow_iface()
    else:
        iface = resolve_flow_iface(iface)

    network_runtime['flow_extractor_udp'] = f"{udp_host}:{udp_port}"
    network_runtime['flow_extractor_iface'] = iface

    def _run():
        try:
            network_runtime['flow_extractor_started'] = True
            network_runtime['flow_extractor_error'] = None
            network_runtime['flow_extractor_start_ts'] = time.time()
            logger.info(f" Starting flow extractor (iface={iface or 'auto'}, udp={udp_host}:{udp_port})")
            log_to_db('INFO', 'FLOW_EXTRACTOR', f"Starting (iface={iface or 'auto'}, udp={udp_host}:{udp_port})", 'startup')
            start_flow_capture(interface=iface, udp_addr=(udp_host, udp_port), l3_socket=l3_socket)
        except Exception as e:
            network_runtime['flow_extractor_error'] = str(e)
            logger.error(f"Flow extractor failed: {e}")
            log_to_db('ERROR', 'FLOW_EXTRACTOR', f"Failed: {str(e)}", 'startup')

    threading.Thread(target=_run, daemon=True).start()

# ============================================================================
# SYSTEM LOGGING HELPER
# ============================================================================

def log_to_db(level, component, message, source='system'):
    """Log system events to database"""
    try:
        cur = db_conn.cursor()
        cur.execute('''
            INSERT INTO system_logs (timestamp, level, component, message, source)
            VALUES (?, ?, ?, ?, ?)
        ''', (time.time(), level.upper(), component, message, source))
        db_conn.commit()
    except Exception as e:
        logger.error(f"Error logging to DB: {e}")

# ============================================================================
# ROUTE HANDLERS - Detection Endpoints
# ============================================================================

@app.route('/')
def index():
    """Serve dashboard index.html"""
    try:
        return send_from_directory('../frontend', 'index.html')
    except Exception as e:
        logger.error(f"Error serving index: {e}")
        return jsonify({'error': 'Dashboard not found'}), 404

@app.route('/history')
def history_page():
    """Serve history page"""
    try:
        return send_from_directory('../frontend', 'cmd_history.html')
    except Exception as e:
        logger.error(f"Error serving history: {e}")
        return jsonify({'error': 'History page not found'}), 404

@app.route('/cmd-history')
def cmd_history_page():
    """Serve CMD history page"""
    try:
        return send_from_directory('../frontend', 'cmd_history.html')
    except Exception as e:
        logger.error(f"Error serving cmd history: {e}")
        return jsonify({'error': 'CMD history page not found'}), 404

@app.route('/system-logs')
def system_logs_page():
    """Serve system logs page"""
    try:
        return send_from_directory('../frontend', 'system_logs.html')
    except Exception as e:
        logger.error(f"Error serving system logs: {e}")
        return jsonify({'error': 'System logs page not found'}), 404

@app.route('/api/health', methods=['GET'])
def api_health():
    """Health check endpoint"""
    detector_info = {
        'regex_patterns': 47,
        'ai_model': False,
        'method': 'none'
    }
    
    if cmd_detector:
        detector_info['method'] = 'hybrid'
        detector_info['ai_model'] = cmd_detector.ai_detector.is_loaded if cmd_detector.ai_detector else False
    
    system_monitor_active = bool(system_monitor and system_monitor.monitoring)

    return jsonify({
        'status': 'healthy',
        'detector': detector_info,
        'ml_mode': detector_info.get('method', 'none'),
        'cmd_patterns': detector_info.get('regex_patterns', 0),
        'timestamp': datetime.now().isoformat(),
        'database': DB_PATH,
        'system_monitor_active': system_monitor_active,
        'ai_trainer_available': AI_TRAINER_AVAILABLE
    }), 200

@app.route('/api/network-status', methods=['GET'])
def api_network_status():
    """Network capture diagnostics"""
    enabled = os.environ.get('ENABLE_FLOW_EXTRACTOR', '1').strip() == '1'
    iface = os.environ.get('FLOW_EXTRACTOR_IFACE') or None
    udp_host = os.environ.get('FLOW_EXTRACTOR_UDP_HOST', '127.0.0.1')
    udp_port = int(os.environ.get('FLOW_EXTRACTOR_UDP_PORT', '9999'))

    ifaces = []
    if SCAPY_AVAILABLE:
        try:
            ifaces = get_if_list()
        except Exception:
            ifaces = []

    win_ifaces = []
    if os.name == 'nt':
        try:
            from scapy.arch.windows import get_windows_if_list
            win_ifaces = get_windows_if_list() or []
            win_ifaces = [
                {
                    'name': i.get('name'),
                    'description': i.get('description'),
                    'guid': i.get('guid'),
                    'ips': i.get('ips')
                }
                for i in win_ifaces
            ]
        except Exception:
            win_ifaces = []

    return jsonify({
        'flow_extractor_available': FLOW_EXTRACTOR_AVAILABLE,
        'flow_extractor_enabled': enabled,
        'flow_extractor_iface': iface,
        'flow_extractor_udp': f"{udp_host}:{udp_port}",
        'flow_extractor_started': bool(network_runtime.get('flow_extractor_started', False)),
        'flow_extractor_runtime_iface': network_runtime.get('flow_extractor_iface'),
        'flow_extractor_runtime_udp': network_runtime.get('flow_extractor_udp'),
        'flow_extractor_error': network_runtime.get('flow_extractor_error'),
        'flow_extractor_start_ts': float(network_runtime.get('flow_extractor_start_ts') or 0.0),
        'udp_flows_received': int(network_runtime.get('udp_flows_received') or 0),
        'last_udp_flow_ts': float(network_runtime.get('last_udp_flow_ts') or 0.0),
        'scapy_available': SCAPY_AVAILABLE,
        'scapy_ifaces': ifaces,
        'windows_ifaces': win_ifaces
    }), 200

@app.route('/api/test-cmd', methods=['POST'])
def api_test_cmd():
    """Test command for malicious patterns using hybrid detector"""
    try:
        data = request.json
        command = data.get('command', '')
        detection_method = data.get('method', 'hybrid')
        
        if not command:
            return jsonify({'error': 'No command provided'}), 400
        
        if not cmd_detector:
            return jsonify({'error': 'Detector not available'}), 503
        
        # Use hybrid detector
        result = cmd_detector.detect(command, method=detection_method)
        result['command'] = command
        
        # Save to database
        try:
            cur = db_conn.cursor()
            cur.execute('''
                INSERT INTO cmd_detections 
                (timestamp, command, severity, confidence, reason, matched_pattern, detection_method, regex_matched, ai_score)
                VALUES (?,?,?,?,?,?,?,?,?)
            ''', (
                time.time(),
                command[:500],
                result.get('severity', 'unknown'),
                result.get('confidence', 0),
                result.get('reason', ''),
                result.get('matched_pattern', ''),
                result.get('combined_method', detection_method),
                1 if result.get('is_malicious', False) else 0,
                result.get('ai_score', 0)
            ))
            db_conn.commit()
        except Exception as e:
            logger.error(f"Error saving CMD detection: {e}")
        
        is_malicious = result.get('is_malicious', False)
        severity = result.get('severity', 'unknown').upper()
        confidence = result.get('confidence', 0) * 100
        
        if is_malicious:
            logger.warning(f" Port scan detected: {severity} | {confidence:.1f}% | {command[:60]}")
        else:
            logger.info(f" BENIGN | {confidence:.1f}% | {command[:60]}")
        
        # Emit via SocketIO
        socketio.emit('alert', {
            'type': 'cmd_detection',
            'timestamp': time.time(),
            **result
        })
        
        return jsonify(result), 200
    
    except Exception as e:
        logger.error(f" API test-cmd error: {e}")
        return jsonify({'error': str(e)}), 500

# ============================================================================
# NETWORK FLOW HELPERS (Port Scan + Scoring + Persistence)
# ============================================================================

scan_map = defaultdict(dict)
WINDOW_SECS = 10
SCAN_PORT_THRESHOLD = 6

def detect_portscan(feat):
    """Detect port scanning activity"""
    now_ts = time.time()
    src = feat.get('src_ip')
    dst_port = feat.get('dst_port')

    if src and dst_port is not None:
        ports = scan_map[src]
        ports[int(dst_port)] = now_ts

        stale = [p for p, t in ports.items() if now_ts - t > WINDOW_SECS]
        for p in stale:
            del ports[p]

        unique_ports = len(ports)
        if unique_ports >= SCAN_PORT_THRESHOLD:
            return True, f"portscan:{unique_ports}_ports_in_{WINDOW_SECS}s", unique_ports

    return False, None, 0


NUMERIC_COLS = ['duration', 'pkt_count', 'byte_count', 'src2dst_pkts', 'dst2src_pkts', 'mean_pkt_size']
SLIDING_WINDOW = deque(maxlen=500)

def stat_score_from_feat(feat):
    """Compute z-score-based anomaly score"""
    try:
        vec = [float(feat.get(c, 0.0)) for c in NUMERIC_COLS]

        if len(SLIDING_WINDOW) < 20:
            SLIDING_WINDOW.append(vec)
            return 0.0

        n = len(SLIDING_WINDOW)
        means = [sum(row[i] for row in SLIDING_WINDOW) / n for i in range(len(NUMERIC_COLS))]

        stds = []
        for i in range(len(NUMERIC_COLS)):
            var = sum((row[i] - means[i]) ** 2 for row in SLIDING_WINDOW) / max(1, n - 1)
            stds.append(math.sqrt(var) if var > 1e-9 else 1.0)

        zvals = [abs((vec[i] - means[i]) / (stds[i] if stds[i] > 0 else 1.0)) for i in range(len(NUMERIC_COLS))]
        maxz = max(zvals) if zvals else 0.0

        SLIDING_WINDOW.append(vec)
        return min(1.0, maxz / 6.0)
    except Exception as e:
        logger.warning(f"Statistical scoring error: {e}")
        return 0.0


def ml_score_from_feat(feat):
    """Score network flow using available backend"""
    if flow_ensemble and flow_ensemble.is_ready:
        score, is_attack, reason, model_results = flow_ensemble.score_flow(feat)
        if score is not None:
            return float(score), bool(is_attack), reason, model_results

    if gnn_scorer and gnn_scorer.is_ready:
        score, is_attack, reason = gnn_scorer.score_flow(feat)
        if score is not None:
            return float(score), bool(is_attack), reason, {"gnn": {"score": score, "is_attack": is_attack, "reason": reason}}

    return stat_score_from_feat(feat), False, None, {}


def classify_severity(score, is_anomaly, reason):
    """Classify alert severity"""

    if 'portscan' in (reason or '').lower():
        if score >= SCAN_PORT_THRESHOLD:
            return 'critical' if score >= SCAN_PORT_THRESHOLD + 2 else 'high'
        return 'medium'

    if not is_anomaly:
        return 'low'

    if score >= 0.9:
        return 'critical'
    if score >= 0.7:
        return 'high'
    if score >= 0.5:
        return 'medium'
    return 'low'


def persist_alert(event):
    """Save alert to database"""
    try:
        cur = db_conn.cursor()
        f = event.get('features', {})
        cur.execute('''
            INSERT INTO alerts (timestamp, src_ip, dst_ip, src_port, dst_port, proto,
                                score, is_anomaly, pkt_count, byte_count, duration,
                                mean_pkt_size, reason, severity, raw_json)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
        ''', (
            float(event.get('timestamp', time.time())),
            f.get('src_ip'), f.get('dst_ip'),
            int(f.get('src_port', 0)), int(f.get('dst_port', 0)),
            int(f.get('proto', 0)),
            float(event.get('score', 0.0)),
            1 if event.get('is_anomaly') else 0,
            int(f.get('pkt_count', 0)),
            int(f.get('byte_count', 0)),
            float(f.get('duration', 0.0)),
            float(f.get('mean_pkt_size', 0.0)),
            event.get('reason', ''),
            event.get('severity', 'low'),
            json.dumps(event)
        ))
        db_conn.commit()
    except Exception as e:
        logger.error(f"DB persist error: {e}")


def persist_flow(flow_event):
    try:
        cur = db_conn.cursor()
        f = flow_event.get('features', {})

        cur.execute('''
            INSERT INTO network_flows (timestamp, src_ip, dst_ip, src_port, dst_port, proto,
                                        score, is_anomaly, pkt_count, byte_count, duration,
                                        mean_pkt_size, raw_json)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)
        ''', (
            float(flow_event.get('timestamp', time.time())),
            f.get('src_ip'), f.get('dst_ip'),
            int(f.get('src_port', 0)), int(f.get('dst_port', 0)),
            int(f.get('proto', 0)),
            float(flow_event.get('score', 0.0)),
            1 if flow_event.get('is_anomaly') else 0,
            int(f.get('pkt_count', 0)),
            int(f.get('byte_count', 0)),
            float(f.get('duration', 0.0)),
            float(f.get('mean_pkt_size', 0.0)),
            json.dumps(flow_event)
        ))
        cur.execute("DELETE FROM network_flows WHERE timestamp < ?", (time.time() - 3600,))
        db_conn.commit()
    except Exception as e:
        logger.error(f"DB persist flow error: {e}")


def persist_model_comparison(flow_event):
    try:
        cur = db_conn.cursor()
        f = flow_event.get('features', {})
        results = flow_event.get('model_results') or {}

        ground_truth = flow_event.get('ground_truth')
        label_source = flow_event.get('label_source')
        if ground_truth is None:
            ground_truth, label_source = _extract_ground_truth(
                f,
                f.get('is_anomaly'),
                f.get('severity'),
                None
            )

        def _get(model_name, key, default=None):
            return results.get(model_name, {}).get(key, default)

        iso_pred = _get('isolation_forest', 'is_attack')
        rf_pred = _get('random_forest', 'is_attack')
        gnn_pred = _get('gnn', 'is_attack')
        iso_is_attack_val = None if iso_pred is None else (1 if iso_pred else 0)
        rf_is_attack_val = None if rf_pred is None else (1 if rf_pred else 0)
        gnn_is_attack_val = None if gnn_pred is None else (1 if gnn_pred else 0)

        current_row = {
            'ground_truth': ground_truth,
            'label_source': label_source,
            'iso_is_attack': iso_is_attack_val,
            'iso_score': _get('isolation_forest', 'score'),
            'rf_is_attack': rf_is_attack_val,
            'rf_score': _get('random_forest', 'score'),
            'gnn_is_attack': gnn_is_attack_val,
            'gnn_score': _get('gnn', 'score'),
        }

        metrics_snapshot = compute_model_metrics_snapshot(cur, current_row=current_row)
        metrics = metrics_snapshot.get('models', {})

        def _metric(model_name, key):
            m = metrics.get(model_name, {})
            return m.get(key) if isinstance(m, dict) else None

        cur.execute('''
            INSERT INTO model_comparisons (
                timestamp, src_ip, dst_ip, src_port, dst_port, proto,
                ground_truth, label_source,
                ensemble_score, ensemble_is_attack, ensemble_reason,
                iso_score, iso_is_attack, iso_reason,
                iso_tpr, iso_fpr, iso_confidence, iso_consistency, iso_unique_rate,
                iso_tp, iso_fp, iso_tn, iso_fn, iso_samples,
                rf_score, rf_is_attack, rf_reason,
                rf_tpr, rf_fpr, rf_confidence, rf_consistency, rf_unique_rate,
                rf_tp, rf_fp, rf_tn, rf_fn, rf_samples,
                gnn_score, gnn_is_attack, gnn_reason,
                gnn_tpr, gnn_fpr, gnn_confidence, gnn_consistency, gnn_unique_rate,
                gnn_tp, gnn_fp, gnn_tn, gnn_fn, gnn_samples,
                raw_json
            )
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
        ''', (
            float(flow_event.get('timestamp', time.time())),
            f.get('src_ip'), f.get('dst_ip'),
            int(f.get('src_port', 0)), int(f.get('dst_port', 0)),
            int(f.get('proto', 0)),
            ground_truth,
            label_source,
            _get('ensemble', 'score'),
            1 if _get('ensemble', 'is_attack') else 0,
            _get('ensemble', 'reason', ''),
            _get('isolation_forest', 'score'),
            iso_is_attack_val,
            _get('isolation_forest', 'reason', ''),
            _metric('isolation_forest', 'tpr'),
            _metric('isolation_forest', 'fpr'),
            _metric('isolation_forest', 'confidence'),
            _metric('isolation_forest', 'consistency'),
            _metric('isolation_forest', 'unique_rate'),
            _metric('isolation_forest', 'tp'),
            _metric('isolation_forest', 'fp'),
            _metric('isolation_forest', 'tn'),
            _metric('isolation_forest', 'fn'),
            _metric('isolation_forest', 'samples'),
            _get('random_forest', 'score'),
            rf_is_attack_val,
            _get('random_forest', 'reason', ''),
            _metric('random_forest', 'tpr'),
            _metric('random_forest', 'fpr'),
            _metric('random_forest', 'confidence'),
            _metric('random_forest', 'consistency'),
            _metric('random_forest', 'unique_rate'),
            _metric('random_forest', 'tp'),
            _metric('random_forest', 'fp'),
            _metric('random_forest', 'tn'),
            _metric('random_forest', 'fn'),
            _metric('random_forest', 'samples'),
            _get('gnn', 'score'),
            gnn_is_attack_val,
            _get('gnn', 'reason', ''),
            _metric('gnn', 'tpr'),
            _metric('gnn', 'fpr'),
            _metric('gnn', 'confidence'),
            _metric('gnn', 'consistency'),
            _metric('gnn', 'unique_rate'),
            _metric('gnn', 'tp'),
            _metric('gnn', 'fp'),
            _metric('gnn', 'tn'),
            _metric('gnn', 'fn'),
            _metric('gnn', 'samples'),
            json.dumps(flow_event)
        ))
        db_conn.commit()
    except Exception as e:
        logger.error(f"DB persist model comparison error: {e}")


@app.route('/api/network-flows', methods=['GET'])
def api_network_flows():
    """Get recent network flows (all traffic)"""
    try:
        limit = int(request.args.get('limit', 200))
        cur = db_conn.cursor()
        cur.execute("SELECT * FROM network_flows ORDER BY timestamp DESC LIMIT ?", (limit,))
        rows = cur.fetchall()
        keys = ['id', 'timestamp', 'src_ip', 'dst_ip', 'src_port', 'dst_port',
                'proto', 'score', 'is_anomaly', 'pkt_count', 'byte_count',
                'duration', 'mean_pkt_size']
        flows = []
        for row in rows:
            flow = dict(zip(keys, row))
            try:
                raw_json = row['raw_json'] if isinstance(row, sqlite3.Row) else row[13]
                if raw_json:
                    raw = json.loads(raw_json)
                    if isinstance(raw, dict):
                        if 'reason' in raw:
                            flow['reason'] = raw.get('reason')
                        if 'severity' in raw:
                            flow['severity'] = raw.get('severity')
                        if 'is_anomaly' in raw:
                            flow['is_anomaly'] = 1 if raw.get('is_anomaly') else 0
                        if 'score' in raw:
                            flow['score'] = raw.get('score', flow.get('score', 0.0))
                        if 'model_results' in raw:
                            flow['model_results'] = raw.get('model_results')
            except Exception:
                pass
            flows.append(flow)
        return jsonify({'flows': flows, 'count': len(flows)}), 200
    except Exception as e:
        logger.error(f" API network-flows error: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/system-logs', methods=['GET'])
def api_system_logs():
    try:
        limit = int(request.args.get('limit', 200))
        level = (request.args.get('level') or '').strip().upper()
        component = (request.args.get('component') or '').strip()
        source = (request.args.get('source') or '').strip()

        where = []
        params = []

        if level:
            where.append('level = ?')
            params.append(level)
        if component:
            where.append('component = ?')
            params.append(component)
        if source:
            where.append('source = ?')
            params.append(source)

        sql = 'SELECT * FROM system_logs'
        if where:
            sql += ' WHERE ' + ' AND '.join(where)
        sql += ' ORDER BY timestamp DESC LIMIT ?'
        params.append(limit)

        cur = db_conn.cursor()
        cur.execute(sql, tuple(params))
        rows = cur.fetchall()

        logs = []
        for r in rows:
            logs.append({
                'id': r[0],
                'timestamp': r[1],
                'level': r[2],
                'component': r[3],
                'message': r[4],
                'source': r[5]
            })

        return jsonify({'logs': logs, 'count': len(logs)}), 200
    except Exception as e:
        logger.error(f" API system-logs error: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/logs-stats', methods=['GET'])
def api_logs_stats():
    try:
        cur = db_conn.cursor()
        cur.execute("SELECT level, COUNT(*) FROM system_logs GROUP BY level")
        by_level = {row[0]: int(row[1]) for row in cur.fetchall()}
        cur.execute("SELECT COUNT(*) FROM system_logs")
        total = int(cur.fetchone()[0] or 0)
        return jsonify({'total': total, 'by_level': by_level}), 200
    except Exception as e:
        logger.error(f" API logs-stats error: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/log-event', methods=['POST'])
def api_log_event():
    try:
        data = request.json or {}
        level = (data.get('level') or 'INFO').strip().upper()
        component = (data.get('component') or 'SIMULATOR').strip()
        message = (data.get('message') or '').strip()
        source = (data.get('source') or 'simulator').strip()

        if not message:
            return jsonify({'error': 'message is required'}), 400

        ts = time.time()
        log_to_db(level, component, message, source)

        socketio.emit('system_log', {
            'timestamp': ts,
            'level': level,
            'component': component,
            'message': message,
            'source': source
        })

        return jsonify({'ok': True}), 200
    except Exception as e:
        logger.error(f" API log-event error: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/cmd-detections', methods=['GET'])
def api_cmd_detections():
    """Get CMD detections"""
    try:
        limit = int(request.args.get('limit', 50))
        cur = db_conn.cursor()
        cur.execute('SELECT * FROM cmd_detections ORDER BY timestamp DESC LIMIT ?', (limit,))
        rows = cur.fetchall()
        detections = []
        for row in rows:
            detections.append({
                'id': row[0],
                'timestamp': row[1],
                'command': row[2],
                'severity': row[3],
                'confidence': row[4],
                'reason': row[5],
                'detection_method': row[7]
            })
        return jsonify({'detections': detections, 'count': len(detections)}), 200
    except Exception as e:
        logger.error(f" API cmd-detections error: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/alerts', methods=['GET'])
def api_alerts():
    """Get recent network alerts"""
    try:
        limit = int(request.args.get('limit', 200))
        cur = db_conn.cursor()
        cur.execute('SELECT * FROM alerts ORDER BY timestamp DESC LIMIT ?', (limit,))
        rows = cur.fetchall()
        keys = ['id', 'timestamp', 'src_ip', 'dst_ip', 'src_port', 'dst_port',
                'proto', 'score', 'is_anomaly', 'pkt_count', 'byte_count',
                'duration', 'mean_pkt_size', 'reason', 'severity']
        alerts = [dict(zip(keys, row)) for row in rows]
        return jsonify({'alerts': alerts, 'count': len(alerts)}), 200
    except Exception as e:
        logger.error(f" API alerts error: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/model-comparisons', methods=['GET'])
def api_model_comparisons():
    """Get per-model scoring comparisons"""
    try:
        limit = int(request.args.get('limit', 200))
        cur = db_conn.cursor()
        cur.execute('SELECT * FROM model_comparisons ORDER BY timestamp DESC LIMIT ?', (limit,))
        rows = cur.fetchall()
        keys = [
            'id', 'timestamp', 'src_ip', 'dst_ip', 'src_port', 'dst_port', 'proto',
            'ground_truth', 'label_source',
            'ensemble_score', 'ensemble_is_attack', 'ensemble_reason',
            'iso_score', 'iso_is_attack', 'iso_reason',
            'iso_tpr', 'iso_fpr', 'iso_confidence', 'iso_consistency', 'iso_unique_rate',
            'iso_tp', 'iso_fp', 'iso_tn', 'iso_fn', 'iso_samples',
            'rf_score', 'rf_is_attack', 'rf_reason',
            'rf_tpr', 'rf_fpr', 'rf_confidence', 'rf_consistency', 'rf_unique_rate',
            'rf_tp', 'rf_fp', 'rf_tn', 'rf_fn', 'rf_samples',
            'gnn_score', 'gnn_is_attack', 'gnn_reason',
            'gnn_tpr', 'gnn_fpr', 'gnn_confidence', 'gnn_consistency', 'gnn_unique_rate',
            'gnn_tp', 'gnn_fp', 'gnn_tn', 'gnn_fn', 'gnn_samples',
            'raw_json'
        ]
        results = []
        for row in rows:
            entry = dict(zip(keys, row))
            try:
                raw_json = entry.get('raw_json')
                if raw_json:
                    raw = json.loads(raw_json)
                    if isinstance(raw, dict):
                        entry['model_results'] = raw.get('model_results')
            except Exception:
                pass
            results.append(entry)
        return jsonify({'comparisons': results, 'count': len(results)}), 200
    except Exception as e:
        logger.error(f" API model-comparisons error: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/model-metrics', methods=['GET'])
def api_model_metrics():
    """Get rolling model performance metrics"""
    try:
        window = int(request.args.get('window', MODEL_METRICS_WINDOW))
        cur = db_conn.cursor()
        snapshot = compute_model_metrics_snapshot(cur, window=window)
        snapshot['computed_at'] = datetime.now().isoformat()
        return jsonify(snapshot), 200
    except Exception as e:
        logger.error(f" API model-metrics error: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/stats', methods=['GET'])
def api_stats():
    """Get combined statistics"""
    try:
        cur = db_conn.cursor()
        cur.execute("SELECT severity, COUNT(*) FROM alerts GROUP BY severity")
        alert_stats = {row[0]: row[1] for row in cur.fetchall()}
        cur.execute("SELECT COUNT(*) FROM cmd_detections")
        cmd_total = cur.fetchone()[0] or 0
        cur.execute("SELECT COUNT(*) FROM cmd_detections WHERE severity = 'critical'")
        cmd_critical = cur.fetchone()[0] or 0

        return jsonify({
            'total_alerts': sum(alert_stats.values()),
            'critical_count': alert_stats.get('critical', 0),
            'high_count': alert_stats.get('high', 0),
            'cmd_detections': cmd_total,
            'cmd_critical': cmd_critical
        }), 200
    except Exception as e:
        logger.error(f" API stats error: {e}")
        return jsonify({'error': str(e)}), 500
# UDP LISTENER (Network Flow Monitoring)
# ============================================================================

def udp_listener(host='0.0.0.0', port=9999):
    """Listen for network flow data via UDP"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.bind((host, port))
        logger.info(f" Listening for flows on UDP {port}")
        log_to_db('INFO', 'UDP_LISTENER', f'Listening on UDP port {port}', 'startup')
        
        while True:
            try:
                data, _ = s.recvfrom(65536)
                feat = json.loads(data.decode())

                network_runtime['udp_flows_received'] = int(network_runtime.get('udp_flows_received') or 0) + 1
                network_runtime['last_udp_flow_ts'] = time.time()
                 
                now_ts = time.time()
                
                # Port scan detection (temporarily disabled to stop repeated alerts)
                scan_detected, scan_reason, scan_score = False, None, 0
                
                if scan_detected:
                    scan_event = {
                        'key': feat.get('key'),
                        'score': float(scan_score),
                        'is_anomaly': True,
                        'timestamp': now_ts,
                        'features': feat,
                        'src_ip': feat.get('src_ip'),
                        'dst_ip': feat.get('dst_ip'),
                        'src_port': feat.get('src_port'),
                        'dst_port': feat.get('dst_port'),
                        'proto': feat.get('proto'),
                        'pkt_count': feat.get('pkt_count'),
                        'byte_count': feat.get('byte_count'),
                        'duration': feat.get('duration'),
                        'mean_pkt_size': feat.get('mean_pkt_size'),
                        'reason': scan_reason,
                        'severity': classify_severity(scan_score, True, scan_reason)
                    }
                    persist_alert(scan_event)
                    socketio.emit('alert', scan_event)
                    logger.warning(f" Port scan detected: {scan_reason}")
                    log_to_db('WARNING', 'PORT_SCAN', f'Detected: {scan_reason}', 'detector')
                    
                    scan_map[feat.get('src_ip')] = {}
                
                # ML scoring
                incoming_score = feat.get('score', None)
                incoming_is_anomaly = feat.get('is_anomaly', None)
                incoming_reason = feat.get('reason', '')
                incoming_severity = str(feat.get('severity', '') or '').strip().lower()

                score, is_attack, ml_reason, model_results = ml_score_from_feat(feat)

                # Normalize alert score to avoid constant 0.95-1.00 on benign traffic.
                # Use margin-above-threshold for ISO/RF (if available) and require a
                # minimum margin before raising an alert.
                is_labeled = feat.get('ground_truth') is not None
                min_margin = 0.03 if is_labeled else 0.10
                full_scale_margin = 0.15 if is_labeled else 0.25
                calibrated_score = None
                calibrated_is_attack = None
                try:
                    iso_item = (model_results or {}).get('isolation_forest') or {}
                    rf_item = (model_results or {}).get('random_forest') or {}

                    iso_pred = iso_item.get('is_attack')
                    rf_pred = rf_item.get('is_attack')

                    iso_score = iso_item.get('score')
                    rf_score = rf_item.get('score')
                    
                    # Ensure scores are floats if they exist
                    if iso_score is not None:
                        try:
                            iso_score = float(iso_score)
                        except (ValueError, TypeError):
                            iso_score = 0.0
                            
                    if rf_score is not None:
                        try:
                            rf_score = float(rf_score)
                        except (ValueError, TypeError):
                            rf_score = 0.0

                    iso_excess = None
                    rf_excess = None

                    if iso_score is not None and flow_ensemble is not None:
                        iso_excess = max(0.0, float(iso_score) - float(flow_ensemble.iso_score_threshold))
                    if rf_score is not None and flow_ensemble is not None:
                        rf_excess = max(0.0, float(rf_score) - float(flow_ensemble.rf_threshold))

                    candidates = [v for v in (iso_excess, rf_excess) if v is not None]
                    if candidates:
                        calibrated_score = float(min(1.0, max(0.0, max(candidates) / float(full_scale_margin))))

                    if is_labeled:
                        if (iso_pred is True) or (rf_pred is True):
                            margin_ok = bool(candidates) and (max(candidates) >= float(min_margin))
                            calibrated_is_attack = bool(margin_ok)
                        else:
                            calibrated_is_attack = False
                    else:
                        iso_ok = (iso_pred is True) and (iso_excess is not None) and (iso_excess >= float(min_margin))
                        rf_ok = (rf_pred is True) and (rf_excess is not None) and (rf_excess >= float(min_margin))
                        calibrated_is_attack = bool(iso_ok and rf_ok)

                    pkt_count = feat.get('pkt_count')
                    byte_count = feat.get('byte_count')
                    duration = feat.get('duration')
                    try:
                        pkt_count = int(pkt_count) if pkt_count is not None else 0
                    except Exception:
                        pkt_count = 0
                    try:
                        byte_count = int(byte_count) if byte_count is not None else 0
                    except Exception:
                        byte_count = 0
                    try:
                        duration = float(duration) if duration is not None else 0.0
                    except Exception:
                        duration = 0.0

                    if pkt_count <= 2 and byte_count <= 2000 and duration <= 2.0:
                        calibrated_is_attack = False
                        if calibrated_score is not None:
                            calibrated_score = float(min(calibrated_score, 0.2))
                except Exception:
                    calibrated_score = None
                    calibrated_is_attack = None

                if calibrated_score is not None and incoming_score is None:
                    score = float(calibrated_score)
                if calibrated_is_attack is not None and incoming_is_anomaly is None:
                    is_attack = bool(calibrated_is_attack)

                if incoming_score is not None:
                    try:
                        score = float(incoming_score)
                    except Exception:
                        pass

                if incoming_is_anomaly is not None:
                    is_attack = bool(incoming_is_anomaly)
                elif incoming_severity in ('high', 'critical'):
                    is_attack = True
                elif incoming_score is not None and score >= 0.7:
                    is_attack = True

                reason = incoming_reason or (ml_reason or '')
                severity = incoming_severity or classify_severity(score, is_attack, reason)
                 
                flow_event = {
                    'key': feat.get('key'),
                    'score': float(score),
                    'is_anomaly': bool(is_attack),
                    'timestamp': feat.get('timestamp', now_ts),
                    'features': feat,
                    'src_ip': feat.get('src_ip'),
                    'dst_ip': feat.get('dst_ip'),
                    'src_port': feat.get('src_port'),
                    'dst_port': feat.get('dst_port'),
                    'proto': feat.get('proto'),
                    'pkt_count': feat.get('pkt_count'),
                    'byte_count': feat.get('byte_count'),
                    'duration': feat.get('duration'),
                    'mean_pkt_size': feat.get('mean_pkt_size'),
                    'reason': reason,
                    'severity': severity,
                    'model_results': model_results
                }

                ground_truth, label_source = _extract_ground_truth(
                    feat,
                    incoming_is_anomaly,
                    incoming_severity,
                    None
                )
                if ground_truth is not None:
                    flow_event['ground_truth'] = ground_truth
                    flow_event['label_source'] = label_source
                
                if is_attack:
                    flow_event['severity'] = severity

                socketio.emit('network_flow', flow_event)
                persist_flow(flow_event)
                persist_model_comparison(flow_event)

                if is_attack:
                    event = {
                        **flow_event,
                        'reason': (reason or 'ML_anomaly').strip()
                    }
                    persist_alert(event)
                    socketio.emit('alert', event)
                 
                if is_attack:
                    logger.warning(f" Anomaly detected: {severity.upper()} | Score: {score:.2f}")
                    log_to_db('WARNING', 'ML_DETECTOR', f"Anomaly: {event['severity']} | Score: {score:.2f}", 'detector')
                else:
                    logger.debug(f" Normal flow: {feat.get('src_ip')} -> {feat.get('dst_ip')}")
            
            except json.JSONDecodeError:
                logger.error("Invalid JSON received on UDP")
                log_to_db('ERROR', 'UDP_LISTENER', 'Invalid JSON received', 'listener')
            except Exception as e:
                logger.error(f"Error processing flow: {e}")
    
    except Exception as e:
        logger.error(f"UDP listener fatal error: {e}")
        log_to_db('ERROR', 'UDP_LISTENER', f'Fatal error: {str(e)}', 'listener')


# ============================================================================
# MAIN - APPLICATION START
# ============================================================================

if __name__ == '__main__':
    logger.info("=" * 80)
    logger.info("🚀 STARTING COMPLETE IDS DETECTOR SERVER")
    logger.info("=" * 80)
    logger.info("📊 Detection Features:")
    logger.info("   ✅ Network flow analysis (ML + Rules)")
    logger.info("   ✅ System process monitoring")
    logger.info("   ✅ Malicious command detection (47 patterns + AI)")
    logger.info("   ✅ Real-time alerting (SocketIO)")
    logger.info("   ✅ On-demand AI training")
    logger.info("   ✅ System logging & monitoring")
    logger.info("=" * 80)
    
    log_to_db('INFO', 'SERVER', 'IDS Detector Server starting', 'startup')
    
    if system_monitor:
        system_monitor.start_monitoring()
        logger.info("✅ System command monitoring auto-started")
        log_to_db('INFO', 'SYSTEM_MONITOR', 'System monitoring started', 'startup')

    # Start UDP listener
    listener_thread = threading.Thread(target=udp_listener, daemon=True)
    listener_thread.start()
    logger.info("✅ UDP listener thread started")

    start_flow_extractor_background()
    
    # Start Flask server
    logger.info("🌐 Starting Flask/SocketIO server on 0.0.0.0:5000")
    logger.info("📊 Dashboard: http://localhost:5000")
    logger.info("📋 System Logs: http://localhost:5000/system-logs")
    logger.info("🔍 CMD History: http://localhost:5000/cmd-history")
    logger.info("📡 API Endpoints:")
    logger.info("   - POST /api/test-cmd - Test command (hybrid detection)")
    logger.info("   - POST /api/train-ai-model - Train AI on-demand")
    logger.info("   - GET /api/training-history - View training history")
    logger.info("   - GET /api/cmd-detections - View CMD detections")
    logger.info("   - GET /api/network-flows - Live network traffic")
    logger.info("   - GET /api/system-logs - Get system logs")
    logger.info("   - GET /api/logs-stats - Get log statistics")
    logger.info("   - GET /api/stats - Get statistics")
    logger.info("=" * 80)
    
    log_to_db('INFO', 'SERVER', 'Flask/SocketIO server started', 'startup')
    socketio.run(app, host='0.0.0.0', port=5000, debug=False, use_reloader=False)