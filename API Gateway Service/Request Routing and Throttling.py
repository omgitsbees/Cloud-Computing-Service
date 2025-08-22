from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import JSONResponse
from redis import Redis
import httpx
import yaml
from datetime import datetime
import logging
from typing import Dict, Optional
from pydantic import BaseModel

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class RouteConfig(BaseModel):
    target_url: str
    methods: list[str]
    rate_limit: int  # requests per minute
    timeout: float = 30.0

class APIGateway:
    def __init__(self):
        self.app = FastAPI(title="API Gateway Service")
        self.redis = Redis(host='localhost', port=6379, db=0)
        self.routes: Dict[str, RouteConfig] = {}
        self.http_client = httpx.AsyncClient()
        
        # Load route configurations
        self.load_routes()
        
        # Register middleware and routes
        self.app.middleware("http")(self.rate_limit_middleware)
        self.app.add_api_route("/{path:path}", self.route_request, methods=["GET", "POST", "PUT", "DELETE"])

    def load_routes(self):
        """Load route configurations from YAML file"""
        try:
            with open("routes_config.yaml") as f:
                config = yaml.safe_load(f)
                for path, route_config in config["routes"].items():
                    self.routes[path] = RouteConfig(**route_config)
                logger.info(f"Loaded {len(self.routes)} routes")
        except Exception as e:
            logger.error(f"Failed to load routes: {e}")
            raise

    async def rate_limit_middleware(self, request: Request, call_next):
        """Rate limiting middleware using Redis"""
        path = request.url.path
        if path in self.routes:
            client_ip = request.client.host
            key = f"ratelimit:{client_ip}:{path}"
            minute = datetime.now().minute
            
            # Update rate limit counter
            requests = self.redis.incr(f"{key}:{minute}")
            if requests == 1:
                self.redis.expire(f"{key}:{minute}", 60)
            
            # Check if rate limit exceeded
            if requests > self.routes[path].rate_limit:
                return JSONResponse(
                    status_code=429,
                    content={"error": "Rate limit exceeded"}
                )
        
        return await call_next(request)

    async def route_request(self, request: Request, path: str):
        """Route incoming requests to target services"""
        if path not in self.routes:
            raise HTTPException(status_code=404, detail="Route not found")

        route_config = self.routes[path]
        if request.method not in route_config.methods:
            raise HTTPException(status_code=405, detail="Method not allowed")

        try:
            # Forward request to target service
            url = f"{route_config.target_url}/{path}"
            headers = dict(request.headers)
            body = await request.body()
            
            response = await self.http_client.request(
                method=request.method,
                url=url,
                headers=headers,
                content=body,
                timeout=route_config.timeout
            )
            
            return JSONResponse(
                content=response.json(),
                status_code=response.status_code,
                headers=dict(response.headers)
            )
            
        except httpx.TimeoutException:
            raise HTTPException(status_code=504, detail="Gateway timeout")
        except Exception as e:
            logger.error(f"Error routing request: {e}")
            raise HTTPException(status_code=502, detail="Bad gateway")

# Example route configuration (routes_config.yaml):
"""
routes:
  "users":
    target_url: "http://user-service:8080"
    methods: ["GET", "POST"]
    rate_limit: 100
  "products":
    target_url: "http://product-service:8080"
    methods: ["GET"]
    rate_limit: 200
"""

if __name__ == "__main__":
    import uvicorn
    gateway = APIGateway()
    uvicorn.run(gateway.app, host="0.0.0.0", port=8000)