
from flask_sock import Sock
import json
from typing import Set, Dict
import threading

class WebSocketHandler:
    def __init__(self, app):
        self.sock = Sock(app)
        self.clients: Dict[str, Set] = {}
        self.lock = threading.Lock()
        
        @self.sock.route('/ws/hunt')
        def hunt_socket(ws):
            with self.lock:
                # Add client to pool
                hunt_id = ws.receive()  # First message should be hunt ID
                if hunt_id not in self.clients:
                    self.clients[hunt_id] = set()
                self.clients[hunt_id].add(ws)
            
            try:
                while True:
                    # Keep connection alive
                    ws.receive()
            except:
                with self.lock:
                    # Remove client on disconnect
                    if hunt_id in self.clients:
                        self.clients[hunt_id].remove(ws)
                        if not self.clients[hunt_id]:
                            del self.clients[hunt_id]
    
    def broadcast_update(self, hunt_id: str, data: Dict):
        """Send update to all clients monitoring a specific hunt"""
        with self.lock:
            if hunt_id in self.clients:
                message = json.dumps(data)
                for ws in self.clients[hunt_id]:
                    try:
                        ws.send(message)
                    except:
                        # Client will be removed on next receive attempt
                        pass
