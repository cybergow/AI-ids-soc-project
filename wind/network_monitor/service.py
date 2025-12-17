import asyncio
import logging
import time
from typing import Dict, List, Optional
from datetime import datetime
import threading

from .packet_capture import PacketCapture, TrafficAnalyzer
from .data_pipeline import create_data_pipeline
from app.api.websocket import send_realtime_alert

class NetworkMonitoringService:
    """Main network monitoring service that coordinates all components"""
    
    def __init__(self, redis_url: str = "redis://localhost:6379", interface: Optional[str] = None):
        self.logger = logging.getLogger(__name__)
        self.is_running = False
        
        # Initialize components
        self.packet_capture = PacketCapture(interface=interface, callback=self._on_packet_captured)
        self.traffic_analyzer = TrafficAnalyzer()
        self.data_pipeline = create_data_pipeline(redis_url)
        
        # Statistics
        self.stats = {
            "packets_captured": 0,
            "alerts_generated": 0,
            "start_time": None,
            "last_packet_time": None
        }
        
        self.logger.info("Network monitoring service initialized")
    
    def _on_packet_captured(self, packet):
        """Callback when a packet is captured"""
        try:
            # Analyze packet for threats
            analysis_result = self.traffic_analyzer.analyze_packet(packet)
            
            # Update statistics
            self.stats["packets_captured"] += 1
            self.stats["last_packet_time"] = packet.timestamp
            
            # Publish packet to pipeline
            self.data_pipeline.publish_packet(packet)
            
            # Check for alerts and publish them
            if analysis_result["alerts"]:
                for alert in analysis_result["alerts"]:
                    self.stats["alerts_generated"] += 1
                    
                    # Publish to pipeline
                    self.data_pipeline.publish_alert(alert)
                    
                    # Send real-time notification
                    asyncio.create_task(send_realtime_alert(alert))
                    
                    self.logger.warning(f"Security alert generated: {alert.get('type', 'unknown')}")
            
        except Exception as e:
            self.logger.error(f"Error processing packet: {e}")
    
    def start(self, interface: Optional[str] = None, filter_expr: Optional[str] = None):
        """Start the network monitoring service"""
        if self.is_running:
            self.logger.warning("Network monitoring service is already running")
            return
        
        try:
            # Start data pipeline
            self.data_pipeline.start()
            
            # Start packet capture
            self.packet_capture.interface = interface or self.packet_capture.interface
            self.packet_capture.start_capture(filter_expr)
            
            # Update statistics
            self.stats["start_time"] = datetime.now()
            self.is_running = True
            
            self.logger.info(f"Network monitoring service started on interface: {self.packet_capture.interface}")
            
        except Exception as e:
            self.logger.error(f"Failed to start network monitoring service: {e}")
            self.stop()
            raise
    
    def stop(self):
        """Stop the network monitoring service"""
        if not self.is_running:
            return
        
        try:
            # Stop packet capture
            self.packet_capture.stop_capture()
            
            # Stop data pipeline
            self.data_pipeline.stop()
            
            self.is_running = False
            self.logger.info("Network monitoring service stopped")
            
        except Exception as e:
            self.logger.error(f"Error stopping network monitoring service: {e}")
    
    def get_status(self) -> Dict:
        """Get current service status"""
        uptime = None
        if self.stats["start_time"]:
            uptime = (datetime.now() - self.stats["start_time"]).total_seconds()
        
        return {
            "is_running": self.is_running,
            "interface": self.packet_capture.interface,
            "uptime_seconds": uptime,
            "statistics": self.stats.copy(),
            "packet_capture_stats": self.packet_capture.get_packet_stats(),
            "data_pipeline_status": self.data_pipeline.get_status()
        }
    
    def get_recent_alerts(self, count: int = 50) -> List[Dict]:
        """Get recent alerts from the pipeline"""
        return self.data_pipeline.get_alerts(max_count=count)
    
    def get_recent_packets(self, count: int = 100) -> List[Dict]:
        """Get recent packets from the pipeline"""
        packets = self.data_pipeline.get_packets(max_count=count)
        # Convert packet objects to dictionaries
        return [packet if isinstance(packet, dict) else packet.to_dict() for packet in packets]

# Global service instance
_monitoring_service = None

def get_monitoring_service() -> NetworkMonitoringService:
    """Get or create the global monitoring service instance"""
    global _monitoring_service
    if _monitoring_service is None:
        _monitoring_service = NetworkMonitoringService()
    return _monitoring_service

def start_monitoring(interface: Optional[str] = None, filter_expr: Optional[str] = None):
    """Start the global monitoring service"""
    service = get_monitoring_service()
    service.start(interface=interface, filter_expr=filter_expr)
    return service

def stop_monitoring():
    """Stop the global monitoring service"""
    service = get_monitoring_service()
    service.stop()
    return service

def get_monitoring_status() -> Dict:
    """Get status of the global monitoring service"""
    service = get_monitoring_service()
    return service.get_status()
