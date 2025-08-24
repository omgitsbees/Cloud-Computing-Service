from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, BaseSettings, Field
import redis
import json
import uuid
import asyncio
import logging
from datetime import datetime
from typing import Dict, Set, Optional, List, Any

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("websocket_service")

class Settings(BaseSettings):
    """Configuration settings"""
    REDIS_HOST: str = "localhost"
    REDIS_PORT: int = 6379
    REDIS_DB: int = 0
    MAX_CONNECTIONS: int = 10000
    CONNECTION_TIMEOUT: int = 3600  # 1 hour
    
    class Config:
        env_file = ".env"

class Connection(BaseModel):
    """WebSocket connection model"""
    connection_id: str
    client_info: Dict[str, Any]
    connected_at: datetime
    last_seen: datetime
    metadata: Optional[Dict[str, Any]] = None

class WebSocketMessage(BaseModel):
    """WebSocket message model"""
    action: str
    channel: Optional[str] = None
    payload: Optional[Dict[str, Any]] = None

class RedisService:
    """Redis service for pub/sub and connection management"""
    def __init__(self, settings: Settings):
        self.settings = settings
        self.redis = redis.Redis(
            host=settings.REDIS_HOST,
            port=settings.REDIS_PORT,
            db=settings.REDIS_DB,
            decode_responses=True
        )
        self.pubsub = self.redis.pubsub(ignore_subscribe_messages=True)

    async def store_connection(self, connection: Connection) -> bool:
        try:
            key = f"connection:{connection.connection_id}"
            self.redis.setex(
                key,
                self.settings.CONNECTION_TIMEOUT,
                connection.json()
            )
            return True
        except Exception as e:
            logger.error(f"Error storing connection: {e}")
            return False

    async def remove_connection(self, connection_id: str) -> bool:
        try:
            key = f"connection:{connection_id}"
            self.redis.delete(key)
            return True
        except Exception as e:
            logger.error(f"Error removing connection: {e}")
            return False

    async def publish_message(self, channel: str, message: dict) -> bool:
        try:
            self.redis.publish(channel, json.dumps(message))
            return True
        except Exception as e:
            logger.error(f"Error publishing message: {e}")
            return False

    def subscribe_to_channel(self, channel: str):
        self.pubsub.subscribe(channel)

    def unsubscribe_from_channel(self, channel: str):
        self.pubsub.unsubscribe(channel)

class WebSocketManager:
    """WebSocket connection manager"""
    def __init__(self, settings: Settings, redis_service: RedisService):
        self.settings = settings
        self.redis_service = redis_service
        self.active_connections: Dict[str, WebSocket] = {}
        self.connection_channels: Dict[str, Set[str]] = {}

    async def connect(self, websocket: WebSocket, client_id: str) -> str:
        """Handle new WebSocket connection"""
        await websocket.accept()
        connection_id = str(uuid.uuid4())
        
        # Create and store connection
        connection = Connection(
            connection_id=connection_id,
            client_info={"client_id": client_id},
            connected_at=datetime.utcnow(),
            last_seen=datetime.utcnow()
        )
        await self.redis_service.store_connection(connection)
        
        self.active_connections[connection_id] = websocket
        self.connection_channels[connection_id] = set()
        
        return connection_id

    async def disconnect(self, connection_id: str):
        """Handle WebSocket disconnection"""
        if connection_id in self.active_connections:
            # Unsubscribe from all channels
            if connection_id in self.connection_channels:
                for channel in self.connection_channels[connection_id]:
                    self.redis_service.unsubscribe_from_channel(channel)
                del self.connection_channels[connection_id]
            
            # Remove connection
            del self.active_connections[connection_id]
            await self.redis_service.remove_connection(connection_id)

    async def broadcast_message(self, channel: str, message: str):
        """Broadcast message to all subscribers of a channel"""
        for conn_id, channels in self.connection_channels.items():
            if channel in channels and conn_id in self.active_connections:
                try:
                    await self.active_connections[conn_id].send_text(message)
                except Exception as e:
                    logger.error(f"Error broadcasting to {conn_id}: {e}")
                    await self.disconnect(conn_id)

class WebSocketService:
    """Main WebSocket service"""
    def __init__(self):
        self.app = FastAPI(title="AWS Clone - WebSocket Service")
        self.settings = Settings()
        self.redis_service = RedisService(self.settings)
        self.manager = WebSocketManager(self.settings, self.redis_service)

        # Add CORS middleware
        self.app.add_middleware(
            CORSMiddleware,
            allow_origins=["*"],
            allow_credentials=True,
            allow_methods=["*"],
            allow_headers=["*"],
        )

        # Register routes
        self.app.websocket("/ws/{client_id}")(self.websocket_endpoint)
        self.app.on_event("startup")(self.startup_event)

    async def startup_event(self):
        """Initialize background tasks"""
        asyncio.create_task(self.message_broadcaster())

    async def websocket_endpoint(self, websocket: WebSocket, client_id: str):
        """WebSocket endpoint handler"""
        connection_id = await self.manager.connect(websocket, client_id)
        
        try:
            while True:
                data = await websocket.receive_text()
                try:
                    message = WebSocketMessage.parse_raw(data)
                    
                    if message.action == "subscribe" and message.channel:
                        self.manager.connection_channels[connection_id].add(message.channel)
                        self.redis_service.subscribe_to_channel(message.channel)
                        await websocket.send_json({
                            "status": "subscribed",
                            "channel": message.channel
                        })
                        
                    elif message.action == "publish" and message.channel and message.payload:
                        await self.redis_service.publish_message(
                            message.channel,
                            message.payload
                        )
                        
                    elif message.action == "unsubscribe" and message.channel:
                        self.manager.connection_channels[connection_id].discard(message.channel)
                        self.redis_service.unsubscribe_from_channel(message.channel)
                        await websocket.send_json({
                            "status": "unsubscribed",
                            "channel": message.channel
                        })
                    
                except ValueError as e:
                    await websocket.send_json({
                        "error": "Invalid message format",
                        "details": str(e)
                    })
                    
        except WebSocketDisconnect:
            await self.manager.disconnect(connection_id)

    async def message_broadcaster(self):
        """Background task for broadcasting Redis messages"""
        while True:
            message = self.redis_service.pubsub.get_message()
            if message and message["type"] == "message":
                channel = message["channel"]
                await self.manager.broadcast_message(channel, message["data"])
            await asyncio.sleep(0.1)

if __name__ == "__main__":
    import uvicorn
    
    service = WebSocketService()
    uvicorn.run(
        service.app,
        host="0.0.0.0",
        port=8000,
        log_level="info"
    )