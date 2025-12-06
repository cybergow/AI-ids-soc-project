import socket
import json
import threading
import sqlite3
import time
import os
import logging
import numpy as np
import math
from collections import defaultdict, deque
from datetime import datetime
from flask import Flask, send_from_directory, jsonify, request
from flask_socketio import SocketIO
from flask_cors import CORS


# ============================================================================
# LOGGING CONFIGURATION
# ============================================================================


logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


# ============================================================================
# GLOBAL STATE & ML MODEL LOADING
# ============================================================================


scaler = None
model = None
ml_mode = "none"  # 'sklearn' | 'onnx' | 'stat' | 'none'
onnx_session = None


# Model file names (relative to backend/)
SKL_SCALER = "isoforest_scaler.pkl"
SKL_MODEL = "isoforest_model.pkl"
ONNX_MODEL = "isoforest_model.onnx"


logger.info("=" * 80)
logger.info("🚀 IDS DETECTOR SERVER - INITIALIZING")
logger.info("=" * 80)


# Try to load sklearn model
try:
    import joblib
    if os.path.exists(SKL_SCALER) and os.path.exists(SKL_MODEL):
        logger.info(f"📂 Found sklearn model files")
        scaler = joblib.load(SKL_SCALER)
        model = joblib.load(SKL_MODEL)
        ml_mode = "sklearn"
        logger.info("✅ ML mode: sklearn (loaded .pkl files)")
    else:
        logger.warning(f"⚠️  sklearn model files not found (checked {SKL_SCALER}, {SKL_MODEL})")
except Exception as e:
    logger.warning(f"⚠️  sklearn load failed: {e}")


# If sklearn not available, try ONNX (lighter runtime)
if ml_mode != "sklearn":
    try:
        import onnxruntime as ort
        if os.path.exists(ONNX_MODEL):
            logger.info(f"📂 Found ONNX model file")
            onnx_session = ort.InferenceSession(ONNX_MODEL, providers=['CPUExecutionProvider'])
            ml_mode = "onnx"
            logger.info("✅ ML mode: onnx (loaded .onnx model)")
        else:
            logger.warning(f"⚠️  ONNX model file not found ({ONNX_MODEL})")
    except Exception as e:
        logger.warning(f"⚠️  onnxruntime not available: {e}")


# If no ML model, fallback to statistical detector
if ml_mode == "none":
    ml_mode = "stat"
    logger.warning("⚠️  ML mode: stat (lightweight fallback detector)")


logger.info(f"🤖 Selected ML Mode: {ml_mode.upper()}")


# ============================================================================
# FLASK & SOCKETIO SETUP
# ============================================================================


app = Flask(__name__, static_folder="../frontend", static_url_path="/")
CORS(app)
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')


logger.info("✅ Flask app initialized with CORS enabled")


DB_PATH = "alerts.db"


# ============================================================================
# DATABASE INITIALIZATION
# ============================================================================


def init_db():
    """Initialize SQLite database for alert storage"""
    try:
        conn = sqlite3.connect(DB_PATH, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()
       
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
       
        # Create index on timestamp for faster queries
        cur.execute('''
            CREATE INDEX IF NOT EXISTS idx_timestamp ON alerts(timestamp DESC)
        ''')
       
        cur.execute('''
            CREATE INDEX IF NOT EXISTS idx_severity ON alerts(severity)
        ''')
       
        conn.commit()
        logger.info(f"✅ Database initialized: {DB_PATH}")
        return conn
    except Exception as e:
        logger.error(f"❌ Database initialization failed: {e}")
        raise


db_conn = init_db()


# ============================================================================
# ROUTE HANDLERS
# ============================================================================


@app.route('/')
def index():
    """Serve dashboard index.html"""
    logger.info("📄 Serving index.html")
    try:
        return send_from_directory('../frontend', 'index.html')
    except Exception as e:
        logger.error(f"Error serving index: {e}")
        return jsonify({'error': 'Dashboard not found'}), 404


@app.route('/history')
def history_page():
    """Serve history page"""
    logger.info("📄 Serving history.html")
    try:
        return send_from_directory('../frontend', 'history.html')
    except Exception as e:
        logger.error(f"Error serving history: {e}")
        return jsonify({'error': 'History page not found'}), 404


@app.route('/api/health', methods=['GET'])
def api_health():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'ml_mode': ml_mode,
        'timestamp': datetime.now().isoformat(),
        'database': DB_PATH,
        'model_loaded': ml_mode != 'none'
    }), 200


@app.route('/api/alerts', methods=['GET'])
def api_alerts():
    """Retrieve alerts from database with filtering"""
    try:
        limit = int(request.args.get('limit', 200))
        severity = request.args.get('severity')
        src = request.args.get('src')
        dst = request.args.get('dst')
       
        cur = db_conn.cursor()
        q = """SELECT id, timestamp, src_ip, dst_ip, src_port, dst_port, proto,
                score, is_anomaly, pkt_count, byte_count, duration, mean_pkt_size,
                reason, severity FROM alerts"""
       
        params = []
        conds = []
       
        if severity:
            conds.append("severity = ?")
            params.append(severity)
        if src:
            conds.append("src_ip = ?")
            params.append(src)
        if dst:
            conds.append("dst_ip = ?")
            params.append(dst)
       
        if conds:
            q += " WHERE " + " AND ".join(conds)
       
        q += " ORDER BY timestamp DESC LIMIT ?"
        params.append(limit)
       
        cur.execute(q, params)
        rows = cur.fetchall()
       
        keys = ['id', 'timestamp', 'src_ip', 'dst_ip', 'src_port', 'dst_port',
                'proto', 'score', 'is_anomaly', 'pkt_count', 'byte_count',
                'duration', 'mean_pkt_size', 'reason', 'severity']
       
        out = [dict(zip(keys, row)) for row in rows]
        logger.info(f"📊 Retrieved {len(out)} alerts")
       
        return jsonify({'alerts': out, 'count': len(out)}), 200
   
    except Exception as e:
        logger.error(f"❌ API alerts error: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/stats', methods=['GET'])
def api_stats():
    """Get alert statistics"""
    try:
        cur = db_conn.cursor()
       
        cur.execute("SELECT COUNT(*) FROM alerts WHERE severity = 'critical'")
        critical = cur.fetchone()[0] or 0
       
        cur.execute("SELECT COUNT(*) FROM alerts WHERE severity = 'high'")
        high = cur.fetchone()[0] or 0
       
        cur.execute("SELECT COUNT(*) FROM alerts WHERE severity = 'medium'")
        medium = cur.fetchone()[0] or 0
       
        cur.execute("SELECT COUNT(*) FROM alerts WHERE severity = 'low'")
        low = cur.fetchone()[0] or 0
       
        cur.execute("SELECT COUNT(*) FROM alerts")
        total = cur.fetchone()[0] or 0
       
        logger.info(f"📈 Stats: {critical} critical, {high} high, {medium} medium, {low} low")
       
        return jsonify({
            'total_alerts': total,
            'critical': critical,
            'high': high,
            'medium': medium,
            'low': low,
            'ml_mode': ml_mode
        }), 200
   
    except Exception as e:
        logger.error(f"❌ API stats error: {e}")
        return jsonify({'error': str(e)}), 500


# ============================================================================
# RULE-BASED DETECTORS
# ============================================================================


# Port-scan detection (sliding window)
scan_map = defaultdict(dict)  # { src_ip: { dst_port: last_seen_ts, ...}}
WINDOW_SECS = 10
SCAN_PORT_THRESHOLD = 6  # Lower for testing; raise for production


def detect_portscan(feat):
    """Detect port scanning activity"""
    now_ts = time.time()
    src = feat.get('src_ip')
    dst_port = feat.get('dst_port')
   
    # Fallback to key array if dst_port missing
    if dst_port is None:
        k = feat.get('key') or []
        if isinstance(k, (list, tuple)) and len(k) >= 4:
            try:
                dst_port = int(k[3])
            except Exception:
                dst_port = None
   
    if src and dst_port is not None:
        ports = scan_map[src]
        ports[int(dst_port)] = now_ts
       
        # Clean up stale entries
        stale = [p for p, t in ports.items() if now_ts - t > WINDOW_SECS]
        for p in stale:
            del ports[p]
       
        unique_ports = len(ports)
        if unique_ports >= SCAN_PORT_THRESHOLD:
            return True, f"portscan:{unique_ports}_ports_in_{WINDOW_SECS}s", unique_ports
   
    return False, None, 0


# ============================================================================
# STATISTICAL DETECTOR (FALLBACK)
# ============================================================================


NUMERIC_COLS = ['duration', 'pkt_count', 'byte_count', 'src2dst_pkts', 'dst2src_pkts', 'mean_pkt_size']
SLIDING_WINDOW = deque(maxlen=500)
STAT_THRESHOLD = 3.0


def stat_score_from_feat(feat):
    """Compute z-score-based anomaly score"""
    try:
        vec = [float(feat.get(c, 0.0)) for c in NUMERIC_COLS]
       
        if len(SLIDING_WINDOW) < 20:
            SLIDING_WINDOW.append(vec)
            return 0.0
       
        # Compute mean and std
        n = len(SLIDING_WINDOW)
        means = [sum(row[i] for row in SLIDING_WINDOW) / n for i in range(len(NUMERIC_COLS))]
       
        stds = []
        for i in range(len(NUMERIC_COLS)):
            var = sum((row[i] - means[i]) ** 2 for row in SLIDING_WINDOW) / max(1, n - 1)
            stds.append(math.sqrt(var) if var > 1e-9 else 1.0)
       
        # Compute max z-score
        zvals = [abs((vec[i] - means[i]) / (stds[i] if stds[i] > 0 else 1.0)) for i in range(len(NUMERIC_COLS))]
        maxz = max(zvals) if zvals else 0.0
       
        SLIDING_WINDOW.append(vec)
       
        # Normalize to [0, 1]
        score = min(1.0, maxz / 6.0)
        return score
   
    except Exception as e:
        logger.warning(f"Statistical scoring error: {e}")
        return 0.0


# ============================================================================
# ML SCORING
# ============================================================================


def ml_score_from_feat(feat):
    """Return (score, is_attack) using available ML backend"""
    global ml_mode, model, scaler, onnx_session
   
    cols = ['duration', 'pkt_count', 'byte_count', 'src2dst_pkts', 'dst2src_pkts', 'mean_pkt_size', 'tcp_syn', 'tcp_rst']
    vec = [float(feat.get(c, 0)) for c in cols]
   
    X = np.array([vec], dtype=np.float32)
   
    # sklearn branch
    if ml_mode == 'sklearn' and model is not None:
        try:
            if scaler is not None:
                Xs = scaler.transform(X)
            else:
                Xs = X
           
            if hasattr(model, 'predict_proba'):
                proba = float(model.predict_proba(Xs)[0, 1])
                return proba, proba >= 0.5
            else:
                df = float(model.decision_function(Xs)[0])
                anom = -df
                return anom, anom >= 0.5
       
        except Exception as e:
            logger.warning(f"sklearn scoring error: {e}")
            return stat_score_from_feat(feat), False
   
    # ONNX branch
    elif ml_mode == 'onnx' and onnx_session is not None:
        try:
            input_name = onnx_session.get_inputs()[0].name
            out = onnx_session.run(None, {input_name: X})
           
            res = out[0] if isinstance(out, (list, tuple)) else out
           
            # Robust output handling
            try:
                if hasattr(res, "toarray") and callable(getattr(res, "toarray", None)):
                    arr = np.asarray(getattr(res, "toarray")())
                elif hasattr(res, "todense") and callable(getattr(res, "todense", None)):
                    arr = np.asarray(getattr(res, "todense")())
                elif isinstance(res, dict):
                    val = next(iter(res.values()))
                    arr = np.asarray(val)
                else:
                    arr = np.asarray(res)
            except Exception:
                arr = np.asarray(res)
           
            flat = arr.ravel()
            if flat.size == 0:
                score = 0.0
            else:
                score = float(flat[0])
           
            return score, score >= 0.5
       
        except Exception as e:
            logger.warning(f"onnx scoring error: {e}")
            return stat_score_from_feat(feat), False
   
    else:
        # Fallback to statistical
        s = stat_score_from_feat(feat)
        return s, s >= (STAT_THRESHOLD / 6.0)


# ============================================================================
# SEVERITY CLASSIFICATION
# ============================================================================


def classify_severity(score, is_anomaly, reason):
    """Classify alert severity based on score, anomaly flag, and reason"""
    if 'portscan' in (reason or '').lower():
        if score >= SCAN_PORT_THRESHOLD:
            return 'critical' if score >= SCAN_PORT_THRESHOLD + 2 else 'high'
        return 'medium'
   
    if not is_anomaly:
        return 'low'
   
    if score >= 0.9:
        return 'critical'
    elif score >= 0.7:
        return 'high'
    elif score >= 0.5:
        return 'medium'
    else:
        return 'low'


# ============================================================================
# ALERT PERSISTENCE & EMISSION
# ============================================================================


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


# ============================================================================
# UDP LISTENER
# ============================================================================


def udp_listener(host='0.0.0.0', port=9999):
    """Listen for network flow data via UDP"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.bind((host, port))
        logger.info(f"🎧 Listening for flows on UDP {port}")
       
        while True:
            try:
                data, _ = s.recvfrom(65536)
                feat = json.loads(data.decode())
               
                now_ts = time.time()
               
                # ========== Port-scan detection ==========
                scan_detected, scan_reason, scan_score = detect_portscan(feat)
               
                if scan_detected:
                    scan_event = {
                        'key': feat.get('key'),
                        'score': float(scan_score),
                        'is_anomaly': True,
                        'timestamp': now_ts,
                        'features': feat,
                        'reason': scan_reason,
                        'severity': classify_severity(scan_score, True, scan_reason)
                    }
                    persist_alert(scan_event)
                    socketio.emit('alert', scan_event)
                    logger.warning(f"🔴 Port scan detected: {scan_reason}")
                    scan_map[feat.get('src_ip')] = {}  # Cooldown
               
                # ========== ML Scoring ==========
                score, is_attack = ml_score_from_feat(feat)
                severity = classify_severity(score, is_attack, feat.get('reason', ''))
               
                event = {
                    'key': feat.get('key'),
                    'score': float(score),
                    'is_anomaly': bool(is_attack),
                    'timestamp': feat.get('timestamp', now_ts),
                    'features': feat,
                    'reason': feat.get('reason', ''),
                    'severity': severity
                }
               
                if is_attack:
                    event['reason'] = (event.get('reason', '') + ' ML_anomaly').strip()
               
                persist_alert(event)
                socketio.emit('alert', event)
               
                if is_attack:
                    logger.warning(f"🔴 Anomaly detected: {event['severity'].upper()} | Score: {score:.2f}")
                else:
                    logger.debug(f"✅ Normal flow: {feat.get('src_ip')} -> {feat.get('dst_ip')}")
           
            except json.JSONDecodeError:
                logger.error("Invalid JSON received on UDP")
            except Exception as e:
                logger.error(f"Error processing flow: {e}")
   
    except Exception as e:
        logger.error(f"UDP listener fatal error: {e}")


# ============================================================================
# MAIN
# ============================================================================


if __name__ == '__main__':
    logger.info("=" * 80)
    logger.info("🚀 STARTING DETECTOR SERVER")
    logger.info("=" * 80)
   
    # Start UDP listener in background
    listener_thread = threading.Thread(target=udp_listener, daemon=True)
    listener_thread.start()
    logger.info("✅ UDP listener thread started")
   
    # Start Flask/SocketIO server
    logger.info("🌐 Starting Flask/SocketIO server on 0.0.0.0:5000")
    socketio.run(app, host='0.0.0.0', port=5000, debug=False, use_reloader=False)