import json
import time
import logging
from typing import Dict, List, Optional, Callable, Any
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta
import threading
import queue
from concurrent.futures import ThreadPoolExecutor

try:
    import redis
    REDIS_AVAILABLE = True
except ImportError:
    REDIS_AVAILABLE = False
    print("Warning: Redis not available. Install with: pip install redis")

from .packet_capture import NetworkPacket

@dataclass
class StreamMessage:
    """Represents a message in the data pipeline"""
    id: str
    timestamp: datetime
    message_type: str
    data: Dict[str, Any]
    source: str
    processed: bool = False
    
    def to_dict(self) -> Dict:
        result = asdict(self)
        result['timestamp'] = self.timestamp.isoformat()
        return result

class RedisStreamManager:
    """Manages Redis streams for real-time data processing"""
    
    def __init__(self, redis_url: str = "redis://localhost:6379", stream_name: str = "network_stream"):
        self.redis_url = redis_url
        self.stream_name = stream_name
        self.redis_client = None
        self.consumer_group = "network_processors"
        self.consumer_name = f"processor_{int(time.time())}"
        self.logger = logging.getLogger(__name__)
        self._connect()
    
    def _connect(self):
        """Connect to Redis"""
        if not REDIS_AVAILABLE:
            raise ImportError("Redis is required for stream processing. Install with: pip install redis")
        
        try:
            self.redis_client = redis.from_url(self.redis_url, decode_responses=True)
            # Test connection
            self.redis_client.ping()
            self.logger.info("Connected to Redis")
            
            # Create consumer group if it doesn't exist
            try:
                self.redis_client.xgroup_create(self.stream_name, self.consumer_group, id='0', mkstream=True)
                self.logger.info(f"Created consumer group: {self.consumer_group}")
            except redis.ResponseError as e:
                if "BUSYGROUP" not in str(e):
                    raise
                    
        except Exception as e:
            self.logger.error(f"Failed to connect to Redis: {e}")
            raise
    
    def publish_packet(self, packet: NetworkPacket) -> str:
        """Publish a network packet to the stream"""
        message_data = {
            "type": "network_packet",
            "timestamp": packet.timestamp.isoformat(),
            "data": packet.to_dict(),
            "source": "packet_capture"
        }
        
        try:
            message_id = self.redis_client.xadd(self.stream_name, message_data)
            return message_id
        except Exception as e:
            self.logger.error(f"Failed to publish packet: {e}")
            raise
    
    def publish_alert(self, alert_data: Dict) -> str:
        """Publish an alert to the stream"""
        message_data = {
            "type": "security_alert",
            "timestamp": datetime.now().isoformat(),
            "data": alert_data,
            "source": "threat_detector"
        }
        
        try:
            message_id = self.redis_client.xadd(self.stream_name, message_data)
            return message_id
        except Exception as e:
            self.logger.error(f"Failed to publish alert: {e}")
            raise
    
    def read_messages(self, count: int = 10, block_ms: int = 1000) -> List[StreamMessage]:
        """Read messages from the stream"""
        try:
            messages = self.redis_client.xreadgroup(
                self.consumer_group,
                self.consumer_name,
                {self.stream_name: '>'},
                count=count,
                block=block_ms
            )
            
            result = []
            for stream, msgs in messages:
                for msg_id, fields in msgs:
                    message = StreamMessage(
                        id=msg_id,
                        timestamp=datetime.fromisoformat(fields['timestamp']),
                        message_type=fields['type'],
                        data=json.loads(fields['data']) if isinstance(fields['data'], str) else fields['data'],
                        source=fields['source']
                    )
                    result.append(message)
            
            return result
        except Exception as e:
            self.logger.error(f"Failed to read messages: {e}")
            return []
    
    def acknowledge_message(self, message_id: str):
        """Acknowledge that a message has been processed"""
        try:
            self.redis_client.xack(self.stream_name, self.consumer_group, message_id)
        except Exception as e:
            self.logger.error(f"Failed to acknowledge message: {e}")
    
    def get_stream_info(self) -> Dict:
        """Get information about the stream"""
        try:
            info = self.redis_client.xinfo_stream(self.stream_name)
            groups = self.redis_client.xinfo_groups(self.stream_name)
            
            return {
                "stream_name": self.stream_name,
                "length": info.get('length', 0),
                "first_id": info.get('first-id'),
                "last_id": info.get('last-id'),
                "groups": len(groups),
                "consumer_group": self.consumer_group,
                "consumer_name": self.consumer_name
            }
        except Exception as e:
            self.logger.error(f"Failed to get stream info: {e}")
            return {}

class StreamProcessor:
    """Processes messages from the Redis stream"""
    
    def __init__(self, stream_manager: RedisStreamManager, num_workers: int = 4):
        self.stream_manager = stream_manager
        self.num_workers = num_workers
        self.is_running = False
        self.workers = []
        self.executor = ThreadPoolExecutor(max_workers=num_workers)
        self.logger = logging.getLogger(__name__)
        self.handlers = {}
        
    def register_handler(self, message_type: str, handler: Callable):
        """Register a handler for a specific message type"""
        self.handlers[message_type] = handler
    
    def start_processing(self):
        """Start processing messages from the stream"""
        if self.is_running:
            self.logger.warning("Stream processor is already running")
            return
        
        self.is_running = True
        
        def worker():
            while self.is_running:
                try:
                    messages = self.stream_manager.read_messages(count=10, block_ms=1000)
                    
                    for message in messages:
                        try:
                            # Find appropriate handler
                            handler = self.handlers.get(message.message_type)
                            if handler:
                                # Process message asynchronously
                                future = self.executor.submit(self._process_message, message, handler)
                                # You could track futures here if needed
                            else:
                                self.logger.warning(f"No handler for message type: {message.message_type}")
                                # Still acknowledge to prevent blocking
                                self.stream_manager.acknowledge_message(message.id)
                                
                        except Exception as e:
                            self.logger.error(f"Error processing message {message.id}: {e}")
                            # Acknowledge to prevent blocking
                            self.stream_manager.acknowledge_message(message.id)
                            
                except Exception as e:
                    self.logger.error(f"Worker error: {e}")
                    time.sleep(1)  # Prevent rapid error loops
        
        # Start worker threads
        for i in range(self.num_workers):
            worker_thread = threading.Thread(target=worker, daemon=True)
            worker_thread.start()
            self.workers.append(worker_thread)
        
        self.logger.info(f"Started {self.num_workers} stream processing workers")
    
    def stop_processing(self):
        """Stop processing messages"""
        self.is_running = False
        self.executor.shutdown(wait=True)
        self.logger.info("Stream processing stopped")
    
    def _process_message(self, message: StreamMessage, handler: Callable):
        """Process a single message"""
        try:
            result = handler(message)
            # Acknowledge message after successful processing
            self.stream_manager.acknowledge_message(message.id)
            return result
        except Exception as e:
            self.logger.error(f"Handler error for message {message.id}: {e}")
            # Still acknowledge to prevent blocking
            self.stream_manager.acknowledge_message(message.id)
            raise

class DataPipeline:
    """Main data pipeline that coordinates all components"""
    
    def __init__(self, redis_url: str = "redis://localhost:6379"):
        self.stream_manager = RedisStreamManager(redis_url)
        self.stream_processor = StreamProcessor(self.stream_manager)
        self.packet_queue = queue.Queue()
        self.alert_queue = queue.Queue()
        self.logger = logging.getLogger(__name__)
        
        # Register default handlers
        self._register_default_handlers()
    
    def _register_default_handlers(self):
        """Register default message handlers"""
        def handle_packet(message: StreamMessage):
            """Handle network packet messages"""
            packet_data = message.data
            self.packet_queue.put(packet_data)
            self.logger.debug(f"Processed packet from {packet_data.get('src_ip')}")
        
        def handle_alert(message: StreamMessage):
            """Handle alert messages"""
            alert_data = message.data
            self.alert_queue.put(alert_data)
            self.logger.warning(f"Security alert: {alert_data.get('type', 'unknown')}")
        
        self.stream_processor.register_handler("network_packet", handle_packet)
        self.stream_processor.register_handler("security_alert", handle_alert)
    
    def start(self):
        """Start the data pipeline"""
        self.stream_processor.start_processing()
        self.logger.info("Data pipeline started")
    
    def stop(self):
        """Stop the data pipeline"""
        self.stream_processor.stop_processing()
        self.logger.info("Data pipeline stopped")
    
    def publish_packet(self, packet: NetworkPacket):
        """Publish a packet to the pipeline"""
        return self.stream_manager.publish_packet(packet)
    
    def publish_alert(self, alert_data: Dict):
        """Publish an alert to the pipeline"""
        return self.stream_manager.publish_alert(alert_data)
    
    def get_packets(self, max_count: int = 100) -> List[Dict]:
        """Get processed packets from the queue"""
        packets = []
        while not self.packet_queue.empty() and len(packets) < max_count:
            try:
                packet = self.packet_queue.get_nowait()
                packets.append(packet)
            except queue.Empty:
                break
        return packets
    
    def get_alerts(self, max_count: int = 100) -> List[Dict]:
        """Get processed alerts from the queue"""
        alerts = []
        while not self.alert_queue.empty() and len(alerts) < max_count:
            try:
                alert = self.alert_queue.get_nowait()
                alerts.append(alert)
            except queue.Empty:
                break
        return alerts
    
    def get_status(self) -> Dict:
        """Get pipeline status"""
        return {
            "redis_connected": self.stream_manager.redis_client is not None,
            "stream_info": self.stream_manager.get_stream_info(),
            "processor_running": self.stream_processor.is_running,
            "packet_queue_size": self.packet_queue.qsize(),
            "alert_queue_size": self.alert_queue.qsize(),
            "registered_handlers": list(self.stream_processor.handlers.keys())
        }

# Mock implementation for when Redis is not available
class MockDataPipeline:
    """Mock data pipeline for development without Redis"""
    
    def __init__(self, redis_url: str = "redis://localhost:6379"):
        self.packet_queue = queue.Queue()
        self.alert_queue = queue.Queue()
        self.is_running = False
        self.logger = logging.getLogger(__name__)
    
    def start(self):
        """Start the mock pipeline"""
        self.is_running = True
        self.logger.info("Mock data pipeline started")
    
    def stop(self):
        """Stop the mock pipeline"""
        self.is_running = False
        self.logger.info("Mock data pipeline stopped")
    
    def publish_packet(self, packet: NetworkPacket):
        """Publish a packet (mock)"""
        self.packet_queue.put(packet.to_dict())
        return f"mock_id_{int(time.time())}"
    
    def publish_alert(self, alert_data: Dict):
        """Publish an alert (mock)"""
        self.alert_queue.put(alert_data)
        return f"mock_alert_{int(time.time())}"
    
    def get_packets(self, max_count: int = 100) -> List[Dict]:
        """Get processed packets"""
        packets = []
        while not self.packet_queue.empty() and len(packets) < max_count:
            try:
                packet = self.packet_queue.get_nowait()
                packets.append(packet)
            except queue.Empty:
                break
        return packets
    
    def get_alerts(self, max_count: int = 100) -> List[Dict]:
        """Get processed alerts"""
        alerts = []
        while not self.alert_queue.empty() and len(alerts) < max_count:
            try:
                alert = self.alert_queue.get_nowait()
                alerts.append(alert)
            except queue.Empty:
                break
        return alerts
    
    def get_status(self) -> Dict:
        """Get mock pipeline status"""
        return {
            "redis_connected": False,
            "mock_mode": True,
            "processor_running": self.is_running,
            "packet_queue_size": self.packet_queue.qsize(),
            "alert_queue_size": self.alert_queue.qsize()
        }

def create_data_pipeline(redis_url: str = "redis://localhost:6379") -> DataPipeline:
    """Factory function to create data pipeline"""
    if not REDIS_AVAILABLE:
        logging.warning("Redis not available, using mock pipeline")
        return MockDataPipeline(redis_url)
    
    try:
        return DataPipeline(redis_url)
    except Exception as e:
        logging.warning(f"Failed to create Redis pipeline: {e}, using mock pipeline")
        return MockDataPipeline(redis_url)
