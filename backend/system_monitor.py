# backend/system_monitor.py
# Real-time Windows system command monitoring using Event Logs

import sqlite3
import threading
import time
import logging
from datetime import datetime
import wmi
import json
import pythoncom
from collections import deque

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class SystemCommandMonitor:
    """Monitor Windows system for malicious commands in real-time"""
    
    def __init__(self, detector, socketio, db_path='alerts.db'):
        self.db_path = db_path
        self.detector = detector
        self.socketio = socketio
        self.monitoring = False
        self.command_history = deque(maxlen=1000)
        self.command_history_set = set()
    
    def get_process_owner(self, process):
        """Safely get the owner of a process."""
        try:
            owner = process.GetOwner()
            if owner and len(owner) > 0:
                return owner[0]
        except Exception as e:
            logger.debug(f"Could not get owner for PID {process.ProcessId}: {e}")
        return 'N/A'
    
    def analyze_command(self, cmd_data):
        """Analyze command for malicious patterns"""
        command = cmd_data['command']

        # Detect malicious patterns
        detection_result = self.detector.detect(command, method='hybrid')
        is_malicious = detection_result['is_malicious']

        detection_result['command'] = command # Add command to result
        self.persist_alert(detection_result, cmd_data)
        self.emit_socket_alert(detection_result)

        if is_malicious:
            severity = detection_result['severity']
            confidence = detection_result['confidence']
            reason = detection_result['reason']

            alert = {
                'timestamp': cmd_data['timestamp'],
                'severity': severity,
                'command_executed': command[:500],  # Limit length
                'user': cmd_data.get('user', 'SYSTEM'),
                'process_id': cmd_data.get('process_id', 0),
                'parent_process': cmd_data.get('parent_process', 'unknown'),
                'source_type': 'system',
                'reason': reason,
                'confidence': confidence,
                'is_malicious': 1,
                'alert_type': 'Malicious Command'
            }

            logger.warning(f' MALICIOUS COMMAND DETECTED: {command[:100]}')
            logger.warning(f'   Severity: {severity} | Confidence: {confidence:.2f}')
            logger.warning(f'   User: {alert["user"]} | Reason: {reason}')

        return detection_result
    
    def emit_socket_alert(self, result):
        if self.socketio:
            self.socketio.emit('alert', {
                'type': 'cmd_detection',
                'timestamp': time.time(),
                **result
            })

    def persist_alert(self, result, cmd_data):
        """Save alert to database"""
        try:
            conn = sqlite3.connect(self.db_path, check_same_thread=False)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO cmd_detections (timestamp, command, severity, confidence, reason, matched_pattern, detection_method, regex_matched, ai_score, is_malicious)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                time.time(),
                result['command'],
                result['severity'],
                result['confidence'],
                result['reason'],
                result.get('matched_pattern', ''),
                result.get('combined_method', result.get('method', 'unknown')),
                result.get('regex_matched'),
                result.get('ai_score'),
                result.get('is_malicious', False)
            ))
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            logger.error(f'Alert persistence error: {e}')
    
    def monitor_loop(self):
        """Continuous monitoring loop using WMI for real-time process creation events."""
        logger.info('Starting WMI-based system command monitoring...')
        self.monitoring = True
        try:
            pythoncom.CoInitializeEx(0)
            c = wmi.WMI()
            process_watcher = c.Win32_Process.watch_for("creation")
        except Exception as e:
            logger.error(f"Failed to initialize WMI watcher: {e}")
            logger.error("Please ensure the 'wmi' package is installed ('pip install wmi') and you have necessary permissions.")
            self.monitoring = False
            return

        while self.monitoring:
            try:
                new_process = process_watcher(timeout_ms=1000)
                if new_process and hasattr(new_process, 'CommandLine') and new_process.CommandLine:
                    # --- Start of filtering logic ---
                    parent_pid = new_process.ParentProcessId
                    try:
                        parent_process = c.Win32_Process(ProcessId=parent_pid)[0]
                        parent_name = parent_process.Name.lower()
                    except (IndexError, wmi.x_wmi) as e:
                        logger.debug(f"Could not find parent process for PID {parent_pid}: {e}")
                        parent_name = "unknown"

                    # Define a blacklist of common noisy processes to exclude
                    ignored_parents = ['chrome.exe', 'firefox.exe', 'msedge.exe', 'svchost.exe']
                    
                    if parent_name in ignored_parents:
                        logger.debug(f"Skipping command from ignored parent '{parent_name}': {new_process.CommandLine}")
                        continue

                    # Also, ignore the script itself if it's being run in a loop
                    if 'python' in parent_name and 'detector_server.py' in new_process.CommandLine:
                        continue
                    # --- End of filtering logic ---

                    cmd_line = new_process.CommandLine
                    if cmd_line in self.command_history_set:
                        continue

                    if len(self.command_history) == self.command_history.maxlen:
                        old = self.command_history.popleft()
                        self.command_history_set.discard(old)

                    self.command_history.append(cmd_line)
                    self.command_history_set.add(cmd_line)

                    cmd_data = {
                        'command': cmd_line,
                        'user': self.get_process_owner(new_process),
                        'process_id': new_process.ProcessId,
                        'parent_process': new_process.ParentProcessId,
                        'timestamp': time.time()
                    }
                    self.analyze_command(cmd_data)

            except wmi.x_wmi_timed_out:
                continue
            except Exception as e:
                logger.error(f'Error in WMI monitor loop: {e}')
                time.sleep(2) # Avoid rapid-fire errors
    
    def start_monitoring(self):
        """Start monitoring in background thread"""
        if not self.monitoring:
            thread = threading.Thread(target=self.monitor_loop, daemon=True)
            thread.start()
            logger.info(' System monitoring thread started')
            logger.info('✅ System monitoring thread started')
    
    def stop_monitoring(self):
        """Stop monitoring"""
        self.monitoring = False
        logger.info('⏹ System monitoring stopped')
    
    def get_alerts(self, limit=50, severity=None):
        """Retrieve system alerts from database"""
        try:
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            if severity:
                cursor.execute('''
                    SELECT * FROM system_alerts 
                    WHERE severity = ?
                    ORDER BY timestamp DESC LIMIT ?
                ''', (severity, limit))
            else:
                cursor.execute('''
                    SELECT * FROM system_alerts 
                    ORDER BY timestamp DESC LIMIT ?
                ''', (limit,))
            
            alerts = [dict(row) for row in cursor.fetchall()]
            conn.close()
            return alerts
        
        except Exception as e:
            logger.error(f'Get alerts error: {e}')
            return []
    
    def get_stats(self):
        """Get system alert statistics"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('SELECT COUNT(*) FROM system_alerts WHERE severity="critical"')
            critical = cursor.fetchone()[0] or 0
            
            cursor.execute('SELECT COUNT(*) FROM system_alerts WHERE severity="high"')
            high = cursor.fetchone()[0] or 0
            
            cursor.execute('SELECT COUNT(*) FROM system_alerts WHERE is_malicious=1')
            malicious_cmd = cursor.fetchone()[0] or 0
            
            cursor.execute('SELECT COUNT(*) FROM system_alerts')
            total = cursor.fetchone()[0] or 0
            
            conn.close()
            
            return {
                'critical_count': critical,
                'high_count': high,
                'malicious_cmd_count': malicious_cmd,
                'process_anomaly_count': 0,  # Can be extended
                'total_system_alerts': total
            }
        
        except Exception as e:
            logger.error(f'Get stats error: {e}')
            return {
                'critical_count': 0,
                'high_count': 0,
                'malicious_cmd_count': 0,
                'process_anomaly_count': 0,
                'total_system_alerts': 0
            }
    
if __name__ == '__main__':
    from cmd_detector_hybrid import HybridCMDDetector
    detector = HybridCMDDetector()
    monitor = SystemCommandMonitor(detector=detector)
    monitor.start_monitoring()
    
    # Keep running
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        monitor.stop_monitoring()
        logger.info('Monitor stopped by user')