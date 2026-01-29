"""
COMPLETE INTEGRATED IDS-SOC DETECTOR SERVER
Detection Engine + API Server + Real-time Dashboard
Combines: Network Flow Analysis + Command Detection + System Monitoring
Author: AI-IDS SOC Team
Date: January 29, 2026
Status: Production Ready
Location: Root directory of AI-ids-soc-project
"""

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
    logger.info("✅ System command monitor initialized")
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
        
        # Create indexes
        cur.execute('''
            CREATE INDEX IF NOT EXISTS idx_timestamp ON alerts(timestamp DESC)
        ''')

        cur.execute('''
            CREATE INDEX IF NOT EXISTS idx_flow_timestamp ON network_flows(timestamp DESC)
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
    'flow_extractor_udp': None,
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
        'flow_extractor_start_ts': float(network_runtime.get('flow_extractor_start_ts', 0.0)),
        'udp_flows_received': int(network_runtime.get('udp_flows_received', 0)),
        'last_udp_flow_ts': float(network_runtime.get('last_udp_flow_ts', 0.0)),
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
    return stat_score_from_feat(feat), False


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

# ============================================================================
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

                network_runtime['udp_flows_received'] = int(network_runtime.get('udp_flows_received', 0)) + 1
                network_runtime['last_udp_flow_ts'] = time.time()
                 
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
                    logger.warning(f" Port scan detected: {scan_reason}")
                    log_to_db('WARNING', 'PORT_SCAN', f'Detected: {scan_reason}', 'detector')
                    
                    scan_map[feat.get('src_ip')] = {}
                
                # ML scoring
                incoming_score = feat.get('score', None)
                incoming_is_anomaly = feat.get('is_anomaly', None)
                incoming_reason = feat.get('reason', '')
                incoming_severity = str(feat.get('severity', '') or '').strip().lower()

                score, is_attack = ml_score_from_feat(feat)
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

                severity = incoming_severity or classify_severity(score, is_attack, incoming_reason)
                 
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
                    'reason': incoming_reason,
                    'severity': severity
                }
                 
                if is_attack:
                    flow_event['severity'] = severity

                socketio.emit('network_flow', flow_event)
                persist_flow(flow_event)

                if is_attack:
                    event = {
                        **flow_event,
                        'reason': (incoming_reason or 'ML_anomaly').strip()
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