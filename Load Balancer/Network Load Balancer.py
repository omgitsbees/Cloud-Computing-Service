import asyncio
import ipaddress
import logging
import json
import yaml
from typing import Dict, List, Optional, Set, Tuple
from dataclasses import dataclass
from datetime import datetime
import socket
import struct
import ctypes
import netfilterqueue
from scapy.all import IP, TCP, UDP, Raw
from fastapi import FastAPI, HTTPException, WebSocket
from pydantic import BaseModel, Field
import uvicorn
import prometheus_client as prom
from concurrent.futures import ThreadPoolExecutor
import pyroute2
from pyroute2 import IPRoute
import hashlib

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("nlb")

# Prometheus metrics
CONNECTIONS_TOTAL = prom.Counter('nlb_connections_total', 'Total connections handled', ['protocol'])
ACTIVE_CONNECTIONS = prom.Gauge('nlb_active_connections', 'Currently active connections', ['protocol'])
BYTES_TRANSFERRED = prom.Counter('nlb_bytes_transferred', 'Total bytes transferred', ['direction'])
TARGET_HEALTH = prom.Gauge('nlb_target_health', 'Target health status', ['target'])

@dataclass
class Connection:
    """Connection tracking class"""
    source_ip: str
    source_port: int
    target_ip: str
    target_port: int
    protocol: str
    start_time: datetime
    last_seen: datetime
    bytes_in: int = 0
    bytes_out: int = 0
    state: str = "NEW"

class TargetGroup(BaseModel):
    """Target group configuration"""
    name: str
    protocol: str
    port: int
    targets: List[str]
    health_check: dict = Field(default_factory=lambda: {
        "protocol": "TCP",
        "port": 80,
        "interval": 30,
        "timeout": 5,
        "healthy_threshold": 3,
        "unhealthy_threshold": 3
    })
    algorithm: str = "round_robin"  # round_robin, least_connections, source_ip_hash

class NLBConfig(BaseModel):
    """Network Load Balancer configuration"""
    name: str
    listeners: List[dict]
    target_groups: List[TargetGroup]
    cross_zone: bool = True
    enable_tcp_termination: bool = False
    enable_udp_support: bool = True

class NetworkLoadBalancer:
    def __init__(self):
        self.app = FastAPI(title="Network Load Balancer")
        self.connections: Dict[str, Connection] = {}
        self.target_groups: Dict[str, TargetGroup] = {}
        self.target_health: Dict[str, Dict[str, str]] = {}
        self.connection_counts: Dict[str, int] = {}
        self.iproute = IPRoute()
        self.executor = ThreadPoolExecutor(max_workers=4)
        
        # Initialize routes and start services
        self._init_routes()
        self._init_prometheus()

    def _init_routes(self):
        @self.app.post("/v1/load_balancer")
        async def create_load_balancer(config: NLBConfig):
            return await self._create_load_balancer(config)

        @self.app.get("/v1/target_groups/{name}/health")
        async def get_target_health(name: str):
            return self.target_health.get(name, {})

        @self.app.websocket("/v1/monitoring")
        async def monitoring_websocket(websocket: WebSocket):
            await self._handle_monitoring(websocket)

    def _init_prometheus(self):
        """Initialize Prometheus metrics server"""
        prom.start_http_server(8001)

    async def _create_load_balancer(self, config: NLBConfig):
        """Create a new load balancer configuration"""
        try:
            # Store target groups
            for tg in config.target_groups:
                self.target_groups[tg.name] = tg
                self.target_health[tg.name] = {target: "unknown" for target in tg.targets}
                self.connection_counts.update({target: 0 for target in tg.targets})

            # Start health checking
            asyncio.create_task(self._health_checker())
            
            # Start packet processing
            self._setup_nfqueue()
            
            return {"status": "created", "name": config.name}
        except Exception as e:
            logger.error(f"Error creating load balancer: {e}")
            raise HTTPException(status_code=500, detail=str(e))

    def _setup_nfqueue(self):
        """Setup netfilter queue for packet processing"""
        try:
            self.nfqueue = netfilterqueue.NetfilterQueue()
            self.nfqueue.bind(1, self._packet_handler)
            
            # Add iptables rules
            self._setup_iptables()
            
            # Start queue in separate thread
            self.executor.submit(self.nfqueue.run)
            
        except Exception as e:
            logger.error(f"Error setting up nfqueue: {e}")
            raise

    def _setup_iptables(self):
        """Setup iptables rules for packet interception"""
        rules = [
            "iptables -A INPUT -p tcp --dport 80 -j NFQUEUE --queue-num 1",
            "iptables -A INPUT -p tcp --dport 443 -j NFQUEUE --queue-num 1",
            "iptables -A INPUT -p udp --dport 53 -j NFQUEUE --queue-num 1"
        ]
        
        for rule in rules:
            try:
                subprocess.run(rule.split(), check=True)
            except subprocess.CalledProcessError as e:
                logger.error(f"Error setting up iptables rule: {e}")

    def _packet_handler(self, packet):
        """Handle intercepted packets"""
        try:
            ip_packet = IP(packet.get_payload())
            
            if ip_packet.haslayer(TCP):
                self._handle_tcp(packet, ip_packet)
            elif ip_packet.haslayer(UDP):
                self._handle_udp(packet, ip_packet)
            
        except Exception as e:
            logger.error(f"Error handling packet: {e}")
            packet.drop()

    def _handle_tcp(self, packet, ip_packet):
        """Handle TCP packets"""
        tcp = ip_packet[TCP]
        conn_id = f"{ip_packet.src}:{tcp.sport}-{ip_packet.dst}:{tcp.dport}"
        
        if conn_id not in self.connections:
            # New connection - select target
            target = self._select_target(ip_packet.src, tcp.dport)
            if not target:
                packet.drop()
                return
            
            self.connections[conn_id] = Connection(
                source_ip=ip_packet.src,
                source_port=tcp.sport,
                target_ip=target,
                target_port=tcp.dport,
                protocol="TCP",
                start_time=datetime.utcnow(),
                last_seen=datetime.utcnow()
            )
            CONNECTIONS_TOTAL.labels(protocol="tcp").inc()
            ACTIVE_CONNECTIONS.labels(protocol="tcp").inc()
            
        connection = self.connections[conn_id]
        connection.last_seen = datetime.utcnow()
        
        # Update metrics
        if ip_packet.src == connection.source_ip:
            connection.bytes_in += len(ip_packet)
            BYTES_TRANSFERRED.labels(direction="in").inc(len(ip_packet))
        else:
            connection.bytes_out += len(ip_packet)
            BYTES_TRANSFERRED.labels(direction="out").inc(len(ip_packet))
        
        # Modify packet destination
        ip_packet.dst = connection.target_ip
        tcp.dport = connection.target_port
        
        # Update checksums
        del ip_packet[TCP].chksum
        del ip_packet.chksum
        packet.set_payload(bytes(ip_packet))
        packet.accept()

    def _handle_udp(self, packet, ip_packet):
        """Handle UDP packets"""
        udp = ip_packet[UDP]
        target = self._select_target(ip_packet.src, udp.dport)
        
        if not target:
            packet.drop()
            return
        
        # Modify packet destination
        ip_packet.dst = target
        
        # Update checksums
        del ip_packet[UDP].chksum
        del ip_packet.chksum
        packet.set_payload(bytes(ip_packet))
        packet.accept()
        
        CONNECTIONS_TOTAL.labels(protocol="udp").inc()

    def _select_target(self, source_ip: str, port: int) -> Optional[str]:
        """Select target based on algorithm"""
        for tg_name, tg in self.target_groups.items():
            if port == tg.port:
                healthy_targets = [
                    t for t in tg.targets
                    if self.target_health[tg_name][t] == "healthy"
                ]
                
                if not healthy_targets:
                    return None
                
                if tg.algorithm == "round_robin":
                    return self._round_robin_select(healthy_targets)
                elif tg.algorithm == "least_connections":
                    return self._least_connections_select(healthy_targets)
                elif tg.algorithm == "source_ip_hash":
                    return self._source_ip_hash_select(source_ip, healthy_targets)
                
        return None

    def _round_robin_select(self, targets: List[str]) -> str:
        """Round-robin target selection"""
        target = targets[0]
        targets.append(targets.pop(0))
        return target

    def _least_connections_select(self, targets: List[str]) -> str:
        """Least connections target selection"""
        return min(targets, key=lambda t: self.connection_counts[t])

    def _source_ip_hash_select(self, source_ip: str, targets: List[str]) -> str:
        """Source IP based target selection"""
        hash_value = int(hashlib.md5(source_ip.encode()).hexdigest(), 16)
        return targets[hash_value % len(targets)]

    async def _health_checker(self):
        """Background task for health checking"""
        while True:
            for tg_name, tg in self.target_groups.items():
                for target in tg.targets:
                    is_healthy = await self._check_target_health(target, tg.health_check)
                    old_status = self.target_health[tg_name][target]
                    new_status = "healthy" if is_healthy else "unhealthy"
                    
                    if old_status != new_status:
                        self.target_health[tg_name][target] = new_status
                        TARGET_HEALTH.labels(target=target).set(1 if is_healthy else 0)
                        
                        if not is_healthy:
                            await self._handle_unhealthy_target(target)
            
            await asyncio.sleep(min(tg.health_check["interval"] for tg in self.target_groups.values()))

    async def _check_target_health(self, target: str, health_check: dict) -> bool:
        """Check target health"""
        try:
            if health_check["protocol"] == "TCP":
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(target, health_check["port"]),
                    timeout=health_check["timeout"]
                )
                writer.close()
                await writer.wait_closed()
                return True
        except Exception:
            return False

    async def _handle_unhealthy_target(self, target: str):
        """Handle unhealthy target"""
        # Remove existing connections
        to_remove = []
        for conn_id, conn in self.connections.items():
            if conn.target_ip == target:
                to_remove.append(conn_id)
                ACTIVE_CONNECTIONS.labels(protocol=conn.protocol.lower()).dec()
        
        for conn_id in to_remove:
            del self.connections[conn_id]

    async def _handle_monitoring(self, websocket: WebSocket):
        """Handle WebSocket monitoring connection"""
        await websocket.accept()
        try:
            while True:
                status = {
                    "connections": len(self.connections),
                    "target_health": self.target_health,
                    "connection_counts": self.connection_counts
                }
                await websocket.send_json(status)
                await asyncio.sleep(5)
        except Exception:
            await websocket.close()

if __name__ == "__main__":
    nlb = NetworkLoadBalancer()
    uvicorn.run(nlb.app, host="0.0.0.0", port=8000)