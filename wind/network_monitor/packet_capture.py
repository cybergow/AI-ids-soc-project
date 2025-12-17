import time
import logging
from typing import Dict, List, Optional, Callable
from dataclasses import dataclass
from datetime import datetime
import json
import threading
import queue

try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP, ARP, get_if_list
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    print("Warning: Scapy not available. Install with: pip install scapy")

@dataclass
class NetworkPacket:
    """Represents a captured network packet"""
    timestamp: datetime
    src_ip: str
    dst_ip: str
    src_port: Optional[int]
    dst_port: Optional[int]
    protocol: str
    packet_size: int
    payload: Optional[str]
    interface: str
    
    def to_dict(self) -> Dict:
        return {
            "timestamp": self.timestamp.isoformat(),
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "src_port": self.src_port,
            "dst_port": self.dst_port,
            "protocol": self.protocol,
            "packet_size": self.packet_size,
            "payload": self.payload,
            "interface": self.interface
        }

class PacketCapture:
    """Network packet capture and analysis engine"""
    
    def __init__(self, interface: Optional[str] = None, callback: Optional[Callable] = None):
        self.interface = interface or self._get_default_interface()
        self.callback = callback
        self.is_running = False
        self.capture_thread = None
        self.packet_queue = queue.Queue()
        self.logger = logging.getLogger(__name__)
        
    def _get_default_interface(self) -> str:
        """Get the default network interface"""
        if not SCAPY_AVAILABLE:
            return "eth0"  # Default fallback
            
        interfaces = get_if_list()
        # Filter out loopback and virtual interfaces
        valid_interfaces = [iface for iface in interfaces if not iface.startswith(('lo', 'vmnet', 'veth'))]
        return valid_interfaces[0] if valid_interfaces else "eth0"
    
    def _process_packet(self, packet):
        """Process a captured packet and extract relevant information"""
        try:
            if IP in packet:
                ip_layer = packet[IP]
                timestamp = datetime.now()
                
                # Extract basic IP information
                src_ip = ip_layer.src
                dst_ip = ip_layer.dst
                protocol = ip_layer.proto
                packet_size = len(packet)
                
                # Extract port information
                src_port = None
                dst_port = None
                payload = None
                
                if TCP in packet:
                    src_port = packet[TCP].sport
                    dst_port = packet[TCP].dport
                    protocol = "TCP"
                    # Extract payload if available
                    if packet[TCP].payload:
                        payload = str(packet[TCP].payload)[:100]  # Limit payload size
                        
                elif UDP in packet:
                    src_port = packet[UDP].sport
                    dst_port = packet[UDP].dport
                    protocol = "UDP"
                    if packet[UDP].payload:
                        payload = str(packet[UDP].payload)[:100]
                        
                elif ICMP in packet:
                    protocol = "ICMP"
                    
                # Create packet object
                network_packet = NetworkPacket(
                    timestamp=timestamp,
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    src_port=src_port,
                    dst_port=dst_port,
                    protocol=protocol,
                    packet_size=packet_size,
                    payload=payload,
                    interface=self.interface
                )
                
                # Add to queue for processing
                self.packet_queue.put(network_packet)
                
                # Call callback if provided
                if self.callback:
                    self.callback(network_packet)
                    
        except Exception as e:
            self.logger.error(f"Error processing packet: {e}")
    
    def start_capture(self, filter_expr: Optional[str] = None):
        """Start packet capture"""
        if not SCAPY_AVAILABLE:
            raise ImportError("Scapy is required for packet capture. Install with: pip install scapy")
            
        if self.is_running:
            self.logger.warning("Packet capture is already running")
            return
            
        self.is_running = True
        
        def capture_worker():
            try:
                self.logger.info(f"Starting packet capture on interface: {self.interface}")
                sniff(
                    iface=self.interface,
                    prn=self._process_packet,
                    filter=filter_expr,
                    stop_filter=lambda x: not self.is_running,
                    store=False  # Don't store packets in memory
                )
            except Exception as e:
                self.logger.error(f"Packet capture error: {e}")
            finally:
                self.is_running = False
                self.logger.info("Packet capture stopped")
        
        self.capture_thread = threading.Thread(target=capture_worker, daemon=True)
        self.capture_thread.start()
    
    def stop_capture(self):
        """Stop packet capture"""
        self.is_running = False
        if self.capture_thread and self.capture_thread.is_alive():
            self.capture_thread.join(timeout=5)
        self.logger.info("Packet capture stopped")
    
    def get_packets(self, max_packets: int = 100) -> List[NetworkPacket]:
        """Get captured packets from queue"""
        packets = []
        while not self.packet_queue.empty() and len(packets) < max_packets:
            try:
                packet = self.packet_queue.get_nowait()
                packets.append(packet)
            except queue.Empty:
                break
        return packets
    
    def get_packet_stats(self) -> Dict:
        """Get packet capture statistics"""
        return {
            "interface": self.interface,
            "is_running": self.is_running,
            "queue_size": self.packet_queue.qsize(),
            "scapy_available": SCAPY_AVAILABLE
        }

class TrafficAnalyzer:
    """Analyzes network traffic for anomalies and threats"""
    
    def __init__(self):
        self.connection_tracker = {}
        self.port_scan_detector = PortScanDetector()
        self.dns_detector = DNSAnomalyDetector()
        self.traffic_volume_detector = TrafficVolumeDetector()
        self.logger = logging.getLogger(__name__)
    
    def analyze_packet(self, packet: NetworkPacket) -> Dict:
        """Analyze a single packet for threats"""
        alerts = []
        
        # Check for port scanning
        port_scan_alert = self.port_scan_detector.analyze_packet(packet)
        if port_scan_alert:
            alerts.append(port_scan_alert)
        
        # Check for DNS anomalies
        dns_alert = self.dns_detector.analyze_packet(packet)
        if dns_alert:
            alerts.append(dns_alert)
        
        # Check for traffic volume anomalies
        volume_alert = self.traffic_volume_detector.analyze_packet(packet)
        if volume_alert:
            alerts.append(volume_alert)
        
        # Basic threat detection
        threat_alert = self._basic_threat_detection(packet)
        if threat_alert:
            alerts.append(threat_alert)
        
        return {
            "packet": packet.to_dict(),
            "alerts": alerts,
            "timestamp": datetime.now().isoformat()
        }
    
    def _basic_threat_detection(self, packet: NetworkPacket) -> Optional[Dict]:
        """Basic threat detection rules"""
        alerts = []
        
        # Check for suspicious ports
        suspicious_ports = [22, 23, 135, 139, 445, 1433, 3389, 5432, 6379]
        if packet.dst_port in suspicious_ports:
            alerts.append({
                "type": "suspicious_port_access",
                "severity": "medium",
                "message": f"Access to suspicious port {packet.dst_port} from {packet.src_ip}",
                "src_ip": packet.src_ip,
                "dst_port": packet.dst_port
            })
        
        # Check for large packets (potential exfiltration)
        if packet.packet_size > 1000000:  # 1MB
            alerts.append({
                "type": "large_packet",
                "severity": "high",
                "message": f"Large packet detected: {packet.packet_size} bytes from {packet.src_ip}",
                "src_ip": packet.src_ip,
                "packet_size": packet.packet_size
            })
        
        return alerts if alerts else None

class PortScanDetector:
    """Detects potential port scanning activity"""
    
    def __init__(self, threshold: int = 10, window_seconds: int = 60):
        self.threshold = threshold
        self.window_seconds = window_seconds
        self.scan_tracker = {}
    
    def analyze_packet(self, packet: NetworkPacket) -> Optional[Dict]:
        """Analyze packet for port scanning patterns"""
        if packet.protocol not in ["TCP", "UDP"]:
            return None
        
        src_ip = packet.src_ip
        current_time = time.time()
        
        # Initialize tracking for this IP
        if src_ip not in self.scan_tracker:
            self.scan_tracker[src_ip] = []
        
        # Add this port access
        self.scan_tracker[src_ip].append({
            "timestamp": current_time,
            "dst_port": packet.dst_port
        })
        
        # Clean old entries
        self.scan_tracker[src_ip] = [
            entry for entry in self.scan_tracker[src_ip]
            if current_time - entry["timestamp"] < self.window_seconds
        ]
        
        # Check for port scan pattern
        unique_ports = len(set(entry["dst_port"] for entry in self.scan_tracker[src_ip]))
        if unique_ports >= self.threshold:
            return {
                "type": "port_scan_detected",
                "severity": "high",
                "message": f"Port scan detected from {src_ip}: {unique_ports} ports in {self.window_seconds}s",
                "src_ip": src_ip,
                "unique_ports": unique_ports,
                "time_window": self.window_seconds
            }
        
        return None

class DNSAnomalyDetector:
    """Detects DNS anomalies and suspicious queries"""
    
    def __init__(self):
        self.query_tracker = {}
        self.suspicious_domains = [
            "malware.com", "phishing.net", "botnet.org"
        ]  # In practice, this would be a threat intelligence feed
    
    def analyze_packet(self, packet: NetworkPacket) -> Optional[Dict]:
        """Analyze packet for DNS anomalies"""
        if packet.dst_port != 53 or packet.protocol != "UDP":
            return None
        
        # This is a simplified DNS detection
        # In practice, you'd parse the DNS packet properly
        if packet.payload:
            payload_lower = packet.payload.lower()
            for domain in self.suspicious_domains:
                if domain in payload_lower:
                    return {
                        "type": "suspicious_dns_query",
                        "severity": "high",
                        "message": f"Suspicious DNS query to {domain} from {packet.src_ip}",
                        "src_ip": packet.src_ip,
                        "domain": domain
                    }
        
        return None

class TrafficVolumeDetector:
    """Detects traffic volume anomalies"""
    
    def __init__(self, threshold_mb: int = 100, window_seconds: int = 60):
        self.threshold_mb = threshold_mb
        self.window_seconds = window_seconds
        self.volume_tracker = {}
    
    def analyze_packet(self, packet: NetworkPacket) -> Optional[Dict]:
        """Analyze packet for traffic volume anomalies"""
        src_ip = packet.src_ip
        current_time = time.time()
        
        # Initialize tracking for this IP
        if src_ip not in self.volume_tracker:
            self.volume_tracker[src_ip] = []
        
        # Add this packet
        self.volume_tracker[src_ip].append({
            "timestamp": current_time,
            "size": packet.packet_size
        })
        
        # Clean old entries
        self.volume_tracker[src_ip] = [
            entry for entry in self.volume_tracker[src_ip]
            if current_time - entry["timestamp"] < self.window_seconds
        ]
        
        # Calculate total volume
        total_bytes = sum(entry["size"] for entry in self.volume_tracker[src_ip])
        total_mb = total_bytes / (1024 * 1024)
        
        if total_mb >= self.threshold_mb:
            return {
                "type": "high_traffic_volume",
                "severity": "medium",
                "message": f"High traffic volume from {src_ip}: {total_mb:.2f}MB in {self.window_seconds}s",
                "src_ip": src_ip,
                "volume_mb": total_mb,
                "time_window": self.window_seconds
            }
        
        return None
