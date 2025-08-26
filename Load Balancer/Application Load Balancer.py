import asyncio
import aiohttp
import ssl
import json
import logging
import hashlib
import yaml
from typing import Dict, List, Optional, Set
from dataclasses import dataclass
from datetime import datetime
from fastapi import FastAPI, HTTPException, WebSocket
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
import uvicorn
import aiodocker
import aioredis
from prometheus_client import Counter, Histogram, start_http_server
import jinja2
import subprocess
from pathlib import Path

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("alb")

# Metrics
REQUEST_COUNT = Counter('alb_requests_total', 'Total requests processed', ['target', 'status'])
LATENCY = Histogram('alb_request_latency_seconds', 'Request latency in seconds')
HEALTHY_TARGETS = Counter('alb_healthy_targets', 'Number of healthy targets')

@dataclass
class TargetHealth:
    """Health status of a target"""
    target_id: str
    status: str
    last_check: datetime
    failure_count: int
    success_count: int

class TargetGroup(BaseModel):
    """Target group configuration"""
    name: str
    protocol: str = "http"
    port: int
    health_check_path: str = "/health"
    health_check_interval: int = 30
    healthy_threshold: int = 2
    unhealthy_threshold: int = 3
    targets: List[str] = []
    stickiness_enabled: bool = False
    stickiness_cookie_duration: int = 86400

class ListenerRule(BaseModel):
    """Listener rule configuration"""
    priority: int
    path_pattern: str
    target_group: str
    conditions: Dict[str, List[str]] = Field(default_factory=dict)

class Listener(BaseModel):
    """Listener configuration"""
    port: int
    protocol: str
    ssl_certificate: Optional[str] = None
    rules: List[ListenerRule] = []

class LoadBalancerConfig(BaseModel):
    """Load balancer configuration"""
    name: str
    listeners: List[Listener]
    target_groups: List[TargetGroup]

class ApplicationLoadBalancer:
    def __init__(self):
        self.app = FastAPI(title="Application Load Balancer")
        self.target_groups: Dict[str, TargetGroup] = {}
        self.target_health: Dict[str, Dict[str, TargetHealth]] = {}
        self.session_persistence: Dict[str, str] = {}
        self.redis: Optional[aioredis.Redis] = None
        self.docker: Optional[aiodocker.Docker] = None
        
        # Initialize routes
        self._init_routes()
        
        # Start metrics server
        start_http_server(8001)

    def _init_routes(self):
        @self.app.post("/v1/load_balancer")
        async def create_load_balancer(config: LoadBalancerConfig):
            return await self._create_load_balancer(config)

        @self.app.get("/v1/target_groups/{name}/health")
        async def get_target_health(name: str):
            return await self._get_target_health(name)

        @self.app.post("/v1/target_groups/{name}/targets")
        async def register_targets(name: str, targets: List[str]):
            return await self._register_targets(name, targets)

        @self.app.delete("/v1/target_groups/{name}/targets")
        async def deregister_targets(name: str, targets: List[str]):
            return await self._deregister_targets(name, targets)

        @self.app.websocket("/v1/monitoring")
        async def monitoring_websocket(websocket: WebSocket):
            await self._handle_monitoring(websocket)

    async def _create_load_balancer(self, config: LoadBalancerConfig):
        """Create a new load balancer configuration"""
        try:
            # Store target groups
            for tg in config.target_groups:
                self.target_groups[tg.name] = tg
                self.target_health[tg.name] = {}
                
                # Initialize health checks for targets
                for target in tg.targets:
                    self.target_health[tg.name][target] = TargetHealth(
                        target_id=target,
                        status="initial",
                        last_check=datetime.utcnow(),
                        failure_count=0,
                        success_count=0
                    )

            # Generate HAProxy configuration
            await self._generate_haproxy_config(config)
            
            # Start health checking
            asyncio.create_task(self._health_checker())
            
            return {"status": "created", "name": config.name}
        
        except Exception as e:
            logger.error(f"Error creating load balancer: {e}")
            raise HTTPException(status_code=500, detail=str(e))

    async def _generate_haproxy_config(self, config: LoadBalancerConfig):
        """Generate HAProxy configuration file"""
        template = """
global
    maxconn 50000
    log /dev/log local0
    user haproxy
    group haproxy
    ssl-default-bind-ciphers TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384
    ssl-default-bind-options no-sslv3 no-tlsv10 no-tlsv11

defaults
    log global
    mode http
    option httplog
    option dontlognull
    timeout connect 5000
    timeout client 50000
    timeout server 50000
    errorfile 400 /etc/haproxy/errors/400.http
    errorfile 403 /etc/haproxy/errors/403.http
    errorfile 408 /etc/haproxy/errors/408.http
    errorfile 500 /etc/haproxy/errors/500.http
    errorfile 502 /etc/haproxy/errors/502.http
    errorfile 503 /etc/haproxy/errors/503.http
    errorfile 504 /etc/haproxy/errors/504.http

frontend stats
    bind *:8404
    stats enable
    stats uri /stats
    stats refresh 10s
    stats admin if LOCALHOST

{% for listener in listeners %}
frontend {{ listener.protocol }}-{{ listener.port }}
    bind *:{{ listener.port }} {% if listener.ssl_certificate %}ssl crt {{ listener.ssl_certificate }}{% endif %}
    mode http
    option forwardfor
    
    {% for rule in listener.rules %}
    acl path{{ loop.index }} path_beg {{ rule.path_pattern }}
    use_backend {{ rule.target_group }} if path{{ loop.index }}
    {% endfor %}
{% endfor %}

{% for tg in target_groups %}
backend {{ tg.name }}
    mode http
    balance roundrobin
    option httpchk GET {{ tg.health_check_path }}
    {% if tg.stickiness_enabled %}
    cookie SERVERID insert indirect nocache
    {% endif %}
    
    {% for target in tg.targets %}
    server {{ target | replace(".", "_") }} {{ target }}:{{ tg.port }} check cookie {{ target | replace(".", "_") }}
    {% endfor %}
{% endfor %}
        """
        
        # Render template
        j2_template = jinja2.Template(template)
        haproxy_config = j2_template.render(
            listeners=config.listeners,
            target_groups=config.target_groups
        )
        
        # Write configuration
        with open("/etc/haproxy/haproxy.cfg", "w") as f:
            f.write(haproxy_config)
        
        # Reload HAProxy
        subprocess.run(["systemctl", "reload", "haproxy"])

    async def _health_checker(self):
        """Background task for health checking"""
        async with aiohttp.ClientSession() as session:
            while True:
                for tg_name, tg in self.target_groups.items():
                    for target in tg.targets:
                        try:
                            url = f"http://{target}:{tg.port}{tg.health_check_path}"
                            async with session.get(url, timeout=5) as response:
                                health = self.target_health[tg_name][target]
                                
                                if response.status == 200:
                                    health.success_count += 1
                                    health.failure_count = 0
                                    if health.success_count >= tg.healthy_threshold:
                                        health.status = "healthy"
                                        HEALTHY_TARGETS.inc()
                                else:
                                    await self._handle_unhealthy_target(tg_name, target)
                                    
                        except Exception:
                            await self._handle_unhealthy_target(tg_name, target)
                        
                        health.last_check = datetime.utcnow()
                
                await asyncio.sleep(min(tg.health_check_interval for tg in self.target_groups.values()))

    async def _handle_unhealthy_target(self, tg_name: str, target: str):
        """Handle unhealthy target"""
        health = self.target_health[tg_name][target]
        health.failure_count += 1
        health.success_count = 0
        
        if health.failure_count >= self.target_groups[tg_name].unhealthy_threshold:
            health.status = "unhealthy"
            # Trigger auto-scaling if configured
            await self._handle_auto_scaling(tg_name)

    async def _handle_auto_scaling(self, tg_name: str):
        """Handle auto-scaling based on target health"""
        if not self.docker:
            self.docker = aiodocker.Docker()
        
        healthy_count = sum(
            1 for health in self.target_health[tg_name].values()
            if health.status == "healthy"
        )
        
        if healthy_count < len(self.target_groups[tg_name].targets) / 2:
            # Launch new container
            try:
                container = await self.docker.containers.create(
                    config={
                        "Image": "your-app-image",
                        "ExposedPorts": {"80/tcp": {}},
                    }
                )
                await container.start()
            except Exception as e:
                logger.error(f"Error launching new container: {e}")

    async def _handle_monitoring(self, websocket: WebSocket):
        """Handle WebSocket monitoring connection"""
        await websocket.accept()
        try:
            while True:
                # Send health status updates
                status = {
                    tg_name: {
                        target: {
                            "status": health.status,
                            "last_check": health.last_check.isoformat(),
                            "failure_count": health.failure_count
                        }
                        for target, health in tg_health.items()
                    }
                    for tg_name, tg_health in self.target_health.items()
                }
                await websocket.send_json(status)
                await asyncio.sleep(5)
        except Exception:
            await websocket.close()

    def _calculate_target_hash(self, target: str) -> str:
        """Calculate hash for consistent hashing"""
        return hashlib.md5(target.encode()).hexdigest()

    async def start(self):
        """Start the load balancer"""
        # Initialize Redis connection
        self.redis = await aioredis.create_redis_pool('redis://localhost')
        
        # Start HAProxy
        subprocess.run(["systemctl", "start", "haproxy"])
        
        # Start monitoring
        asyncio.create_task(self._health_checker())

if __name__ == "__main__":
    alb = ApplicationLoadBalancer()
    uvicorn.run(alb.app, host="0.0.0.0", port=8000)