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
from system_monitor import SystemCommandMonitor

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

logger = logging.getLogger(__name__)

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
# GLOBAL STATE & MODEL INITIALIZATION
# ============================================================================

ml_mode = "none"
scaler = None
model = None

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

logger.info("✅ Flask app initialized with CORS enabled")

DB_PATH = "alerts.db"

# ============================================================================
# SYSTEM COMMAND MONITOR INITIALIZATION
# ============================================================================

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
        conn = sqlite3.connect(DB_PATH, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()
        
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
            logger.error(f"❌ Database migration failed (cmd_detections): {e}")
        
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
        
        # Create indexes
        cur.execute('''
            CREATE INDEX IF NOT EXISTS idx_timestamp ON alerts(timestamp DESC)
        ''')
        
        cur.execute('''
            CREATE INDEX IF NOT EXISTS idx_severity ON alerts(severity)
        ''')
        
        cur.execute('''
            CREATE INDEX IF NOT EXISTS idx_cmd_timestamp ON cmd_detections(timestamp DESC)
        ''')
        
        conn.commit()
        logger.info(f"✅ Database initialized: {DB_PATH}")
        return conn
    except Exception as e:
        logger.error(f"❌ Database initialization failed: {e}")
        raise

db_conn = init_db()

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

# TEST COMMAND - Hybrid Detector (Regex + AI)
@app.route('/api/test-cmd', methods=['POST'])
def api_test_cmd():
    """Test command for malicious patterns using hybrid detector"""
    try:
        data = request.json
        command = data.get('command', '')
        detection_method = data.get('method', 'hybrid')  # hybrid, regex, or ai
        
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
            logger.warning(f"🔴 {severity} | {confidence:.1f}% | {command[:60]}")
        else:
            logger.info(f"🟢 BENIGN | {confidence:.1f}% | {command[:60]}")
        
        # Emit via SocketIO
        socketio.emit('alert', {
            'type': 'cmd_detection',
            'timestamp': time.time(),
            **result
        })
        
        return jsonify(result), 200
    
    except Exception as e:
        logger.error(f"❌ API test-cmd error: {e}")
        return jsonify({'error': str(e)}), 500

# TRAIN AI MODEL ON DEMAND
@app.route('/api/train-ai-model', methods=['POST'])
def api_train_ai_model():
    """Train AI model on-demand"""
    if not AI_TRAINER_AVAILABLE:
        return jsonify({'error': 'AI Trainer not available'}), 503
    
    try:
        logger.info("🤖 Starting AI model training...")
        
        trainer = CMDDetectorAIModel(model_type='isolation_forest')
        results = trainer.train()
        trainer.save_model()
        
        # Save training history
        try:
            cur = db_conn.cursor()
            metrics = results.get('metrics', {})
            cur.execute('''
                INSERT INTO ai_training_history 
                (timestamp, model_type, accuracy, precision, recall, f1_score, status)
                VALUES (?,?,?,?,?,?,?)
            ''', (
                time.time(),
                'isolation_forest',
                metrics.get('accuracy', 0),
                metrics.get('precision', 0),
                metrics.get('recall', 0),
                metrics.get('f1_score', 0),
                'success'
            ))
            db_conn.commit()
        except Exception as e:
            logger.error(f"Error saving training history: {e}")
        
        logger.info("✅ AI model training complete and saved")
        
        return jsonify({
            'status': 'success',
            'message': 'AI model trained and saved',
            'metrics': results.get('metrics', {}),
            'timestamp': datetime.now().isoformat()
        }), 200
    
    except Exception as e:
        logger.error(f"❌ Training error: {e}")
        return jsonify({'error': str(e), 'status': 'failed'}), 500

# GET TRAINING HISTORY
@app.route('/api/training-history', methods=['GET'])
def api_training_history():
    """Get AI model training history"""
    try:
        limit = int(request.args.get('limit', 10))
        
        cur = db_conn.cursor()
        cur.execute('''
            SELECT * FROM ai_training_history ORDER BY timestamp DESC LIMIT ?
        ''', (limit,))
        
        rows = cur.fetchall()
        history = []
        
        for row in rows:
            history.append({
                'id': row[0],
                'timestamp': row[1],
                'model_type': row[2],
                'accuracy': row[3],
                'precision': row[4],
                'recall': row[5],
                'f1_score': row[6],
                'status': row[7]
            })
        
        return jsonify({'history': history, 'count': len(history)}), 200
    
    except Exception as e:
        logger.error(f"❌ Training history error: {e}")
        return jsonify({'error': str(e)}), 500

# GET CMD DETECTIONS
@app.route('/api/cmd-detections', methods=['GET'])
def api_cmd_detections():
    """Get CMD detections"""
    try:
        limit = int(request.args.get('limit', 50))
        severity = request.args.get('severity')
        method = request.args.get('method')
        
        cur = db_conn.cursor()
        
        query = 'SELECT * FROM cmd_detections'
        params = []
        conditions = []
        
        if severity:
            conditions.append('severity = ?')
            params.append(severity)
        
        if method:
            conditions.append('detection_method = ?')
            params.append(method)
        
        if conditions:
            query += ' WHERE ' + ' AND '.join(conditions)
        
        query += ' ORDER BY timestamp DESC LIMIT ?'
        params.append(limit)
        
        cur.execute(query, params)
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
        
        logger.info(f"📊 Retrieved {len(detections)} CMD detections")
        return jsonify({'detections': detections, 'count': len(detections)}), 200
    
    except Exception as e:
        logger.error(f"❌ API cmd-detections error: {e}")
        return jsonify({'error': str(e)}), 500

# GET ALERTS
@app.route('/api/alerts', methods=['GET'])
def api_alerts():
    """Retrieve combined alerts (network + system + cmd)"""
    try:
        limit = int(request.args.get('limit', 200))
        severity = request.args.get('severity')
        
        cur = db_conn.cursor()
        q = "SELECT * FROM alerts ORDER BY timestamp DESC LIMIT ?"
        
        cur.execute(q, (limit,))
        rows = cur.fetchall()
        
        keys = ['id', 'timestamp', 'src_ip', 'dst_ip', 'src_port', 'dst_port',
                'proto', 'score', 'is_anomaly', 'pkt_count', 'byte_count',
                'duration', 'mean_pkt_size', 'reason', 'severity']
        
        network_alerts = [dict(zip(keys, row)) for row in rows]
        system_alerts = system_monitor.get_alerts(limit=limit) if system_monitor else []
        
        combined_alerts = network_alerts + system_alerts
        combined_alerts = sorted(combined_alerts, key=lambda x: x.get('timestamp', 0), reverse=True)[:limit]
        
        logger.info(f"📊 Retrieved {len(combined_alerts)} total alerts")
        return jsonify({'alerts': combined_alerts, 'count': len(combined_alerts)}), 200

    except Exception as e:
        logger.error(f"❌ API alerts error: {e}")
        return jsonify({'error': str(e)}), 500

# GET SYSTEM ALERTS
@app.route('/api/system-alerts', methods=['GET'])
def api_system_alerts():
    """Get system alerts only"""
    try:
        limit = int(request.args.get('limit', 100))
        severity = request.args.get('severity')

        if not system_monitor:
            return jsonify({'alerts': [], 'count': 0, 'warning': 'system_monitor_not_available'}), 200

        alerts = system_monitor.get_alerts(limit=limit, severity=severity)
        logger.info(f"📊 Retrieved {len(alerts)} system alerts")
        
        return jsonify({'alerts': alerts, 'count': len(alerts)}), 200
    
    except Exception as e:
        logger.error(f"❌ API system alerts error: {e}")
        return jsonify({'error': str(e)}), 500

# GET STATISTICS
@app.route('/api/stats', methods=['GET'])
def api_stats():
    """Get combined statistics"""
    try:
        cur = db_conn.cursor()
        
        # Network stats
        cur.execute("SELECT severity, COUNT(*) FROM alerts GROUP BY severity")
        alert_stats = {row[0]: row[1] for row in cur.fetchall()}
        
        # CMD detection stats
        cur.execute("SELECT COUNT(*) FROM cmd_detections WHERE severity = 'critical'")
        cmd_critical = cur.fetchone()[0] or 0
        
        cur.execute("SELECT COUNT(*) FROM cmd_detections")
        cmd_total = cur.fetchone()[0] or 0
        
        # Training stats
        cur.execute("SELECT COUNT(*) FROM ai_training_history WHERE status = 'success'")
        training_count = cur.fetchone()[0] or 0
        
        system_stats = system_monitor.get_stats() if system_monitor else {}
        
        detector_status = 'not_loaded'
        if cmd_detector:
            if cmd_detector.ai_detector and cmd_detector.ai_detector.is_loaded:
                detector_status = 'hybrid'
            else:
                detector_status = 'regex_only'
        
        return jsonify({
            'total_alerts': sum(alert_stats.values()),
            'critical_count': alert_stats.get('critical', 0),
            'high_count': alert_stats.get('high', 0),
            'cmd_detections': cmd_total,
            'cmd_critical': cmd_critical,
            'ai_trainings': training_count,
            'detector_type': detector_status,
            'regex_patterns': 47
        }), 200

    except Exception as e:
        logger.error(f"❌ API stats error: {e}")
        return jsonify({'error': str(e)}), 500

# START MONITORING
@app.route('/api/start-monitor', methods=['POST'])
def api_start_monitor():
    """Start monitoring"""
    try:
        if not system_monitor:
            return jsonify({'error': 'System monitor not available'}), 503

        system_monitor.start_monitoring()
        logger.info("✅ Monitoring started (Network + System + CMD)")
        
        return jsonify({
            'status': 'monitoring_started',
            'network': True,
            'system': True,
            'cmd_detection': True,
            'timestamp': datetime.now().isoformat()
        }), 200
    
    except Exception as e:
        logger.error(f"❌ Start monitor error: {e}")
        return jsonify({'error': str(e)}), 500

# STOP MONITORING
@app.route('/api/stop-monitor', methods=['POST'])
def api_stop_monitor():
    """Stop monitoring"""
    try:
        if not system_monitor:
            return jsonify({'error': 'System monitor not available'}), 503

        system_monitor.stop_monitoring()
        logger.info("⏹️ Monitoring stopped")
        
        return jsonify({
            'status': 'monitoring_stopped',
            'timestamp': datetime.now().isoformat()
        }), 200
    
    except Exception as e:
        logger.error(f"❌ Stop monitor error: {e}")
        return jsonify({'error': str(e)}), 500

# ============================================================================
# RULE-BASED DETECTORS (Port Scanning, Etc.)
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

# ============================================================================
# STATISTICAL DETECTOR
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
        
        n = len(SLIDING_WINDOW)
        means = [sum(row[i] for row in SLIDING_WINDOW) / n for i in range(len(NUMERIC_COLS))]
        
        stds = []
        for i in range(len(NUMERIC_COLS)):
            var = sum((row[i] - means[i]) ** 2 for row in SLIDING_WINDOW) / max(1, n - 1)
            stds.append(math.sqrt(var) if var > 1e-9 else 1.0)
        
        zvals = [abs((vec[i] - means[i]) / (stds[i] if stds[i] > 0 else 1.0)) for i in range(len(NUMERIC_COLS))]
        maxz = max(zvals) if zvals else 0.0
        
        SLIDING_WINDOW.append(vec)
        score = min(1.0, maxz / 6.0)
        return score

    except Exception as e:
        logger.warning(f"Statistical scoring error: {e}")
        return 0.0

# ============================================================================
# ML SCORING
# ============================================================================

def ml_score_from_feat(feat):
    """Score network flow using available backend"""
    cols = ['duration', 'pkt_count', 'byte_count', 'src2dst_pkts', 'dst2src_pkts', 'mean_pkt_size', 'tcp_syn', 'tcp_rst']
    vec = [float(feat.get(c, 0)) for c in cols]
    
    # Fallback to statistical scoring
    return stat_score_from_feat(feat), False

# ============================================================================
# SEVERITY CLASSIFICATION
# ============================================================================

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
    elif score >= 0.7:
        return 'high'
    elif score >= 0.5:
        return 'medium'
    else:
        return 'low'

# ============================================================================
# ALERT PERSISTENCE
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
# UDP LISTENER (Network Flow Monitoring)
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
                
                # Port scan detection
                scan_detected, scan_reason, scan_score = detect_portscan(feat)
                
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
                    logger.warning(f"🔴 Port scan detected: {scan_reason}")
                    
                    scan_map[feat.get('src_ip')] = {}
                
                # ML scoring
                score, is_attack = ml_score_from_feat(feat)
                severity = classify_severity(score, is_attack, feat.get('reason', ''))
                
                event = {
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
    logger.info("🚀 STARTING COMPLETE IDS DETECTOR SERVER")
    logger.info("=" * 80)
    logger.info("📊 Detection Features:")
    logger.info("   ✅ Network flow analysis (ML + Rules)")
    logger.info("   ✅ System process monitoring")
    logger.info("   ✅ Malicious command detection (47 patterns + AI)")
    logger.info("   ✅ Real-time alerting (SocketIO)")
    logger.info("   ✅ On-demand AI training")
    logger.info("=" * 80)
    
    if system_monitor:
        system_monitor.start_monitoring()
        logger.info("✅ System command monitoring auto-started")

    # Start UDP listener
    listener_thread = threading.Thread(target=udp_listener, daemon=True)
    listener_thread.start()
    logger.info("✅ UDP listener thread started")
    
    # Start Flask server
    logger.info("🌐 Starting Flask/SocketIO server on 0.0.0.0:5000")
    logger.info("📊 Dashboard: http://localhost:5000")
    logger.info("📡 API Endpoints:")
    logger.info("   - POST /api/test-cmd - Test command (hybrid detection)")
    logger.info("   - POST /api/train-ai-model - Train AI on-demand")
    logger.info("   - GET /api/training-history - View training history")
    logger.info("   - GET /api/cmd-detections - View CMD detections")
    logger.info("   - GET /api/stats - Get statistics")
    logger.info("=" * 80)
    
    socketio.run(app, host='0.0.0.0', port=5000, debug=False, use_reloader=False)