import json
import asyncio
import logging
from typing import Dict, List, Set, Optional
from datetime import datetime
from fastapi import WebSocket, WebSocketDisconnect, Depends
from sqlalchemy.orm import Session
from app.db.session import get_db
from app.core.auth_ws import get_current_user_ws
from app.models.user import User
from app.core.rbac import require_any_authenticated

class ConnectionManager:
    """Manages WebSocket connections for real-time updates"""
    
    def __init__(self):
        self.active_connections: Dict[str, WebSocket] = {}
        self.user_connections: Dict[str, str] = {}  # user_id -> connection_id
        self.logger = logging.getLogger(__name__)
    
    async def connect(self, websocket: WebSocket, user_id: str):
        """Accept and store WebSocket connection"""
        await websocket.accept()
        connection_id = f"{user_id}_{datetime.now().timestamp()}"
        self.active_connections[connection_id] = websocket
        self.user_connections[user_id] = connection_id
        
        self.logger.info(f"WebSocket connected: {connection_id} for user {user_id}")
        
        # Send welcome message
        await self.send_personal_message({
            "type": "connection_established",
            "message": "Connected to real-time monitoring",
            "timestamp": datetime.now().isoformat()
        }, connection_id)
        
        return connection_id
    
    def disconnect(self, connection_id: str):
        """Remove WebSocket connection"""
        if connection_id in self.active_connections:
            user_id = None
            # Find user_id from connection
            for uid, conn_id in self.user_connections.items():
                if conn_id == connection_id:
                    user_id = uid
                    break
            
            del self.active_connections[connection_id]
            if user_id and user_id in self.user_connections:
                del self.user_connections[user_id]
            
            self.logger.info(f"WebSocket disconnected: {connection_id}")
    
    async def send_personal_message(self, message: dict, connection_id: str):
        """Send message to specific connection"""
        if connection_id in self.active_connections:
            websocket = self.active_connections[connection_id]
            try:
                await websocket.send_text(json.dumps(message))
            except Exception as e:
                self.logger.error(f"Error sending message to {connection_id}: {e}")
                # Remove broken connection
                self.disconnect(connection_id)
    
    async def send_user_message(self, message: dict, user_id: str):
        """Send message to all connections for a specific user"""
        connection_id = self.user_connections.get(user_id)
        if connection_id:
            await self.send_personal_message(message, connection_id)
    
    async def broadcast(self, message: dict):
        """Broadcast message to all connected clients"""
        if not self.active_connections:
            return
        
        disconnected = []
        for connection_id, websocket in self.active_connections.items():
            try:
                await websocket.send_text(json.dumps(message))
            except Exception as e:
                self.logger.error(f"Error broadcasting to {connection_id}: {e}")
                disconnected.append(connection_id)
        
        # Clean up disconnected connections
        for connection_id in disconnected:
            self.disconnect(connection_id)
    
    async def broadcast_to_role(self, message: dict, role: str, db: Session):
        """Broadcast message to users with specific role"""
        from app.models.user import User
        
        users = db.query(User).filter(User.role == role).all()
        for user in users:
            await self.send_user_message(message, str(user.id))
    
    def get_connection_stats(self) -> Dict:
        """Get connection statistics"""
        return {
            "total_connections": len(self.active_connections),
            "unique_users": len(self.user_connections),
            "connections": list(self.active_connections.keys())
        }

# Global connection manager instance
manager = ConnectionManager()

class RealtimeAlertStreamer:
    """Handles real-time alert streaming to WebSocket clients"""
    
    def __init__(self, connection_manager: ConnectionManager):
        self.connection_manager = connection_manager
        self.logger = logging.getLogger(__name__)
        self.alert_queue = asyncio.Queue()
        self.packet_queue = asyncio.Queue()
        self.is_running = False
    
    async def start_streaming(self):
        """Start the streaming process"""
        self.is_running = True
        
        # Create tasks for processing queues
        asyncio.create_task(self._process_alerts())
        asyncio.create_task(self._process_packets())
        
        self.logger.info("Real-time alert streaming started")
    
    async def stop_streaming(self):
        """Stop the streaming process"""
        self.is_running = False
        self.logger.info("Real-time alert streaming stopped")
    
    async def queue_alert(self, alert_data: Dict):
        """Queue an alert for streaming"""
        await self.alert_queue.put({
            "type": "security_alert",
            "data": alert_data,
            "timestamp": datetime.now().isoformat()
        })
    
    async def queue_packet(self, packet_data: Dict):
        """Queue a packet for streaming (filtered)"""
        await self.packet_queue.put({
            "type": "network_packet",
            "data": packet_data,
            "timestamp": datetime.now().isoformat()
        })
    
    async def _process_alerts(self):
        """Process alerts from queue and send to clients"""
        while self.is_running:
            try:
                alert_message = await asyncio.wait_for(self.alert_queue.get(), timeout=1.0)
                
                # Broadcast alert to all connected clients
                await self.connection_manager.broadcast(alert_message)
                
                self.logger.info(f"Broadcasted alert: {alert_message['data'].get('type', 'unknown')}")
                
            except asyncio.TimeoutError:
                continue
            except Exception as e:
                self.logger.error(f"Error processing alert: {e}")
    
    async def _process_packets(self):
        """Process packets from queue and send to clients (filtered)"""
        while self.is_running:
            try:
                packet_message = await asyncio.wait_for(self.packet_queue.get(), timeout=1.0)
                
                # Only send packets that are interesting (e.g., suspicious activities)
                packet_data = packet_message['data']
                if self._is_packet_interesting(packet_data):
                    await self.connection_manager.broadcast(packet_message)
                
            except asyncio.TimeoutError:
                continue
            except Exception as e:
                self.logger.error(f"Error processing packet: {e}")
    
    def _is_packet_interesting(self, packet_data: Dict) -> bool:
        """Determine if a packet is interesting enough to stream"""
        # Filter for suspicious ports, large packets, etc.
        suspicious_ports = [22, 23, 135, 139, 445, 1433, 3389, 5432, 6379]
        dst_port = packet_data.get('dst_port')
        packet_size = packet_data.get('packet_size', 0)
        
        return (
            dst_port in suspicious_ports or
            packet_size > 100000 or  # Large packets
            packet_data.get('protocol') == 'ICMP'
        )

# Global streamer instance
streamer = RealtimeAlertStreamer(manager)

async def websocket_endpoint(websocket: WebSocket, token: str, db: Session = Depends(get_db)):
    """WebSocket endpoint for real-time updates"""
    # Authenticate user using token
    try:
        user = await get_current_user_ws(token, db)
    except Exception:
        await websocket.close(code=4001, reason="Authentication failed")
        return
    
    # Check authorization
    if user.role not in ['admin', 'analyst', 'viewer']:
        await websocket.close(code=4003, reason="Insufficient permissions")
        return
    
    # Connect to WebSocket
    connection_id = await manager.connect(websocket, str(user.id))
    
    try:
        # Keep connection alive and handle incoming messages
        while True:
            try:
                # Receive message from client
                data = await websocket.receive_text()
                message = json.loads(data)
                
                # Handle different message types
                await handle_websocket_message(message, user, websocket, db)
                
            except WebSocketDisconnect:
                break
            except Exception as e:
                logger = logging.getLogger(__name__)
                logger.error(f"WebSocket error: {e}")
                break
                
    finally:
        manager.disconnect(connection_id)

async def handle_websocket_message(message: Dict, user: User, websocket: WebSocket, db: Session):
    """Handle incoming WebSocket messages"""
    message_type = message.get('type')
    
    if message_type == 'ping':
        # Respond to ping with pong
        await websocket.send_text(json.dumps({
            'type': 'pong',
            'timestamp': datetime.now().isoformat()
        }))
    
    elif message_type == 'subscribe':
        # Handle subscription to specific events
        await handle_subscription(message, user, websocket, db)
    
    elif message_type == 'get_stats':
        # Send connection statistics
        if user.role == 'admin':
            stats = manager.get_connection_stats()
            await websocket.send_text(json.dumps({
                'type': 'stats',
                'data': stats,
                'timestamp': datetime.now().isoformat()
            }))
    
    else:
        # Unknown message type
        await websocket.send_text(json.dumps({
            'type': 'error',
            'message': f'Unknown message type: {message_type}',
            'timestamp': datetime.now().isoformat()
        }))

async def handle_subscription(message: Dict, user: User, websocket: WebSocket, db: Session):
    """Handle subscription requests"""
    subscription_type = message.get('subscription_type')
    
    if subscription_type == 'alerts':
        # User wants to subscribe to alerts
        await websocket.send_text(json.dumps({
            'type': 'subscription_confirmed',
            'subscription': 'alerts',
            'message': 'You will receive real-time alerts',
            'timestamp': datetime.now().isoformat()
        }))
    
    elif subscription_type == 'packets':
        # Only analysts and admins can subscribe to packet streams
        if user.role in ['admin', 'analyst']:
            await websocket.send_text(json.dumps({
                'type': 'subscription_confirmed',
                'subscription': 'packets',
                'message': 'You will receive real-time packet data',
                'timestamp': datetime.now().isoformat()
            }))
        else:
            await websocket.send_text(json.dumps({
                'type': 'error',
                'message': 'Insufficient permissions for packet subscription',
                'timestamp': datetime.now().isoformat()
            }))
    
    else:
        await websocket.send_text(json.dumps({
            'type': 'error',
            'message': f'Unknown subscription type: {subscription_type}',
            'timestamp': datetime.now().isoformat()
        }))

# Helper functions for external components
async def send_realtime_alert(alert_data: Dict):
    """Send an alert to all connected clients"""
    await streamer.queue_alert(alert_data)

async def send_realtime_packet(packet_data: Dict):
    """Send packet data to connected clients"""
    await streamer.queue_packet(packet_data)

def get_connection_stats() -> Dict:
    """Get current connection statistics"""
    return manager.get_connection_stats()
