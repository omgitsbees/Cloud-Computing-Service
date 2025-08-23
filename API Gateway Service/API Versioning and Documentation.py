from fastapi import FastAPI, Request, HTTPException, Depends, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.openapi.utils import get_openapi
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from typing import Dict, Optional, List
from enum import Enum
import yaml
import logging
from datetime import datetime
import opentelemetry.trace as trace
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import ConsoleSpanExporter
from opentelemetry.sdk.trace.export import BatchSpanProcessor
from .middleware.auth import AuthMiddleware
from .middleware.cache import CacheMiddleware
from .middleware.circuit_breaker import CircuitBreaker
from .middleware.metrics import MetricsMiddleware

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class APIVersion(str, Enum):
    V1 = "v1"
    V2 = "v2"
    V3 = "v3"

class RouteConfig(BaseModel):
    """API Route Configuration"""
    target_url: str = Field(..., description="Target service URL")
    methods: List[str] = Field(..., description="Allowed HTTP methods")
    version: APIVersion = Field(..., description="API version")
    deprecated: bool = Field(False, description="Whether this route is deprecated")
    rate_limit: int = Field(100, description="Requests per minute allowed")
    auth_required: bool = Field(True, description="Whether authentication is required")
    cache_ttl: int = Field(300, description="Cache TTL in seconds for GET requests")

class APIGatewayService:
    def __init__(self):
        # Initialize tracing
        trace.set_tracer_provider(TracerProvider())
        tracer = trace.get_tracer(__name__)
        span_processor = BatchSpanProcessor(ConsoleSpanExporter())
        trace.get_tracer_provider().add_span_processor(span_processor)

        self.app = FastAPI(
            title="Enterprise API Gateway",
            description="API Gateway with versioning, authentication, caching, and monitoring",
            version="1.0.0",
            docs_url="/docs",
            redoc_url="/redoc"
        )

        # Initialize middleware
        self.auth = AuthMiddleware(secret_key="your-secret-key")
        self.cache = CacheMiddleware(redis_url="redis://localhost:6379/0")
        self.circuit_breaker = CircuitBreaker()
        self.metrics = MetricsMiddleware()

        # Add middleware in order
        self.app.middleware("http")(self.metrics)
        self.app.middleware("http")(self.circuit_breaker)
        self.app.middleware("http")(self.cache)
        
        # Configure CORS
        self.app.add_middleware(
            CORSMiddleware,
            allow_origins=["*"],
            allow_credentials=True,
            allow_methods=["*"],
            allow_headers=["*"],
        )

        # Load route configurations
        self.routes: Dict[str, RouteConfig] = self.load_route_config()
        
        # Register routes
        self.register_routes()
        
        # Custom OpenAPI schema
        self.app.openapi = self.custom_openapi

        # Add metrics endpoint
        self.app.get("/metrics")(self.get_metrics)
        self.app.post("/auth/token")(self.create_token)

    def load_route_config(self) -> Dict[str, RouteConfig]:
        """Load route configurations from YAML"""
        try:
            with open("config/route_config.yaml") as f:
                config = yaml.safe_load(f)
                return {
                    path: RouteConfig(**route_config)
                    for path, route_config in config["routes"].items()
                }
        except Exception as e:
            logger.error(f"Failed to load route config: {e}")
            return {}

    def register_routes(self):
        """Register API routes with versioning"""
        for path, config in self.routes.items():
            for method in config.methods:
                endpoint = self.route_handler
                if config.auth_required:
                    endpoint = Depends(self.auth)(endpoint)

                self.app.add_api_route(
                    f"/{config.version}/{path}",
                    endpoint,
                    methods=[method],
                    description=f"{method} {path}",
                    deprecated=config.deprecated,
                    tags=[config.version]
                )

    async def route_handler(self, request: Request):
        """Handle API requests with version support"""
        with trace.get_tracer(__name__).start_as_current_span("route_handler") as span:
            try:
                path_parts = request.url.path.split("/")
                version = path_parts[1]
                path = "/".join(path_parts[2:])
                
                span.set_attribute("path", path)
                span.set_attribute("version", version)
                
                route_config = self.routes.get(path)
                if not route_config:
                    raise HTTPException(status_code=404, detail="Route not found")
                
                if route_config.deprecated:
                    logger.warning(f"Deprecated route accessed: {path}")
                    # Add deprecation warning header
                    headers = {"X-API-Warn": "This endpoint is deprecated"}
                else:
                    headers = {}
                
                return JSONResponse(
                    content={
                        "message": "Request processed",
                        "path": path,
                        "version": version,
                        "timestamp": datetime.utcnow().isoformat()
                    },
                    headers=headers
                )
                
            except Exception as e:
                logger.error(f"Error processing request: {e}")
                span.record_exception(e)
                raise HTTPException(status_code=500, detail="Internal server error")

    async def get_metrics(self):
        """Expose Prometheus metrics"""
        return Response(content=self.metrics.get_metrics(), media_type="text/plain")

    async def create_token(self, request: Request):
        """Create authentication token"""
        try:
            body = await request.json()
            token = self.auth.create_token(body)
            return {"access_token": token, "token_type": "bearer"}
        except Exception as e:
            raise HTTPException(status_code=400, detail="Invalid token request")

    def custom_openapi(self):
        """Generate custom OpenAPI schema"""
        if not hasattr(self, "openapi_schema"):
            openapi_schema = get_openapi(
                title=self.app.title,
                version=self.app.version,
                description=self.app.description,
                routes=self.app.routes,
            )
            
            openapi_schema["info"]["x-versions"] = [v.value for v in APIVersion]
            
            for path, config in self.routes.items():
                if config.deprecated:
                    version_path = f"/{config.version}/{path}"
                    if version_path in openapi_schema["paths"]:
                        openapi_schema["paths"][version_path]["x-deprecated-message"] = (
                            f"This endpoint is deprecated. Please migrate to newer version."
                        )
            
            self.openapi_schema = openapi_schema
        
        return self.openapi_schema

if __name__ == "__main__":
    import uvicorn
    
    gateway = APIGatewayService()
    
    uvicorn.run(
        gateway.app,
        host="0.0.0.0",
        port=8000,
        log_level="info"
    )