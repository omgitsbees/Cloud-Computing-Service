import fastapi
from fastapi import FastAPI, Request, Response, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, validator
import yaml
import json
import xml.etree.ElementTree as ET
import csv
import io
from typing import Dict, List, Any, Optional, Union
from datetime import datetime
import jwt
import logging
import re
from enum import Enum
import jsonschema
import jmespath
import base64
import hashlib
import asyncio
from dataclasses import dataclass
from functools import wraps

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("request_transformer")

class ContentType(str, Enum):
    JSON = "application/json"
    XML = "application/xml"
    CSV = "text/csv"
    FORM = "application/x-www-form-urlencoded"
    TEXT = "text/plain"

class TransformationType(str, Enum):
    FILTER = "filter"
    MAP = "map"
    ENRICH = "enrich"
    VALIDATE = "validate"
    CONVERT = "convert"

@dataclass
class TransformationRule:
    name: str
    type: TransformationType
    config: Dict[str, Any]
    path: str
    conditions: Optional[List[Dict[str, str]]] = None

class TransformationConfig(BaseModel):
    rules: List[TransformationRule]
    schema: Optional[Dict[str, Any]] = None
    content_type: Optional[ContentType] = None
    cache_ttl: Optional[int] = None

class RequestTransformer:
    def __init__(self):
        self.app = FastAPI(title="AWS Clone - Request/Response Transformer")
        self.transformations: Dict[str, TransformationConfig] = {}
        
        # Add CORS middleware
        self.app.add_middleware(
            CORSMiddleware,
            allow_origins=["*"],
            allow_credentials=True,
            allow_methods=["*"],
            allow_headers=["*"],
        )
        
        # Initialize routes
        self._init_routes()
        
    def _init_routes(self):
        @self.app.post("/transform/{path:path}")
        async def transform_request(request: Request, path: str):
            return await self._handle_transformation(request, path, is_response=False)

        @self.app.post("/transform_response/{path:path}")
        async def transform_response(request: Request, path: str):
            return await self._handle_transformation(request, path, is_response=True)

        @self.app.put("/rules/{path}")
        async def update_rules(path: str, config: TransformationConfig):
            self.transformations[path] = config
            return {"status": "updated", "path": path}

    async def _handle_transformation(self, request: Request, path: str, is_response: bool):
        try:
            # Get transformation config
            config = self.transformations.get(path)
            if not config:
                raise HTTPException(status_code=404, detail="No transformation rules found")

            # Parse request body based on content type
            content_type = request.headers.get("content-type", "application/json")
            body = await self._parse_body(request, content_type)

            # Apply transformations
            transformed_data = await self._apply_transformations(
                body, config.rules, is_response
            )

            # Validate against schema if provided
            if config.schema:
                try:
                    jsonschema.validate(transformed_data, config.schema)
                except jsonschema.exceptions.ValidationError as e:
                    raise HTTPException(status_code=422, detail=str(e))

            # Convert to desired content type
            if config.content_type:
                transformed_data = self._convert_content_type(
                    transformed_data, config.content_type
                )
                return Response(
                    content=transformed_data,
                    media_type=config.content_type
                )

            return JSONResponse(content=transformed_data)

        except Exception as e:
            logger.error(f"Transformation error: {str(e)}")
            raise HTTPException(status_code=500, detail=str(e))

    async def _parse_body(self, request: Request, content_type: str) -> Any:
        """Parse request body based on content type"""
        body = await request.body()
        
        if content_type.startswith("application/json"):
            return json.loads(body)
        elif content_type.startswith("application/xml"):
            return self._xml_to_dict(ET.fromstring(body))
        elif content_type.startswith("text/csv"):
            return list(csv.DictReader(io.StringIO(body.decode())))
        elif content_type.startswith("application/x-www-form-urlencoded"):
            return dict(await request.form())
        return body.decode()

    async def _apply_transformations(
        self, data: Any, rules: List[TransformationRule], is_response: bool
    ) -> Any:
        """Apply transformation rules to data"""
        for rule in rules:
            if self._should_apply_rule(data, rule, is_response):
                data = await self._apply_rule(data, rule)
        return data

    def _should_apply_rule(
        self, data: Any, rule: TransformationRule, is_response: bool
    ) -> bool:
        """Check if rule should be applied based on conditions"""
        if not rule.conditions:
            return True

        for condition in rule.conditions:
            field = jmespath.search(condition["field"], data)
            operator = condition["operator"]
            value = condition["value"]

            if not self._evaluate_condition(field, operator, value):
                return False
        return True

    def _evaluate_condition(self, field: Any, operator: str, value: Any) -> bool:
        """Evaluate a single condition"""
        if operator == "eq":
            return field == value
        elif operator == "ne":
            return field != value
        elif operator == "contains":
            return value in field
        elif operator == "matches":
            return bool(re.match(value, str(field)))
        return False

    async def _apply_rule(self, data: Any, rule: TransformationRule) -> Any:
        """Apply a single transformation rule"""
        if rule.type == TransformationType.FILTER:
            return self._filter_data(data, rule.config)
        elif rule.type == TransformationType.MAP:
            return self._map_data(data, rule.config)
        elif rule.type == TransformationType.ENRICH:
            return await self._enrich_data(data, rule.config)
        elif rule.type == TransformationType.VALIDATE:
            return self._validate_data(data, rule.config)
        elif rule.type == TransformationType.CONVERT:
            return self._convert_data(data, rule.config)
        return data

    def _filter_data(self, data: Any, config: Dict[str, Any]) -> Any:
        """Filter fields from data"""
        if isinstance(data, dict):
            return {
                k: v for k, v in data.items()
                if k in config.get("include", data.keys())
                and k not in config.get("exclude", [])
            }
        elif isinstance(data, list):
            return [self._filter_data(item, config) for item in data]
        return data

    def _map_data(self, data: Any, config: Dict[str, Any]) -> Any:
        """Map fields to new names/locations"""
        if not isinstance(data, dict):
            return data

        result = {}
        for new_key, path in config["mappings"].items():
            value = jmespath.search(path, data)
            if value is not None:
                current = result
                parts = new_key.split('.')
                for part in parts[:-1]:
                    current = current.setdefault(part, {})
                current[parts[-1]] = value
        return result

    async def _enrich_data(self, data: Any, config: Dict[str, Any]) -> Any:
        """Enrich data with additional information"""
        if isinstance(data, dict):
            enriched = data.copy()
            if "timestamp" in config.get("add", []):
                enriched["timestamp"] = datetime.utcnow().isoformat()
            if "hash" in config.get("add", []):
                enriched["hash"] = hashlib.sha256(
                    json.dumps(data, sort_keys=True).encode()
                ).hexdigest()
            if "base64" in config.get("encode", []):
                for field in config["encode"]["base64"]:
                    if field in enriched:
                        enriched[field] = base64.b64encode(
                            str(enriched[field]).encode()
                        ).decode()
            return enriched
        return data

    def _validate_data(self, data: Any, config: Dict[str, Any]) -> Any:
        """Validate data against rules"""
        if "schema" in config:
            jsonschema.validate(data, config["schema"])
        if "custom" in config:
            for rule in config["custom"]:
                if not eval(rule["condition"], {"data": data}):
                    raise HTTPException(
                        status_code=422,
                        detail=f"Validation failed: {rule['message']}"
                    )
        return data

    def _convert_data(self, data: Any, config: Dict[str, Any]) -> Any:
        """Convert data types"""
        if isinstance(data, dict):
            return {
                k: self._convert_value(v, config.get("types", {}).get(k))
                for k, v in data.items()
            }
        return data

    def _convert_value(self, value: Any, type_name: Optional[str]) -> Any:
        """Convert a single value to specified type"""
        if not type_name or value is None:
            return value
        
        try:
            if type_name == "int":
                return int(value)
            elif type_name == "float":
                return float(value)
            elif type_name == "bool":
                return bool(value)
            elif type_name == "string":
                return str(value)
            elif type_name == "datetime":
                return datetime.fromisoformat(value)
        except (ValueError, TypeError):
            pass
        return value

    def _xml_to_dict(self, element: ET.Element) -> Dict:
        """Convert XML to dictionary"""
        result = {}
        for child in element:
            if len(child) == 0:
                result[child.tag] = child.text
            else:
                result[child.tag] = self._xml_to_dict(child)
        return result

    def _convert_content_type(self, data: Any, target_type: ContentType) -> str:
        """Convert data to target content type"""
        if target_type == ContentType.JSON:
            return json.dumps(data)
        elif target_type == ContentType.XML:
            root = ET.Element("root")
            self._dict_to_xml(data, root)
            return ET.tostring(root, encoding="unicode")
        elif target_type == ContentType.CSV:
            if not isinstance(data, list):
                raise ValueError("Data must be a list of dictionaries for CSV conversion")
            output = io.StringIO()
            writer = csv.DictWriter(output, fieldnames=data[0].keys())
            writer.writeheader()
            writer.writerows(data)
            return output.getvalue()
        return str(data)

    def _dict_to_xml(self, data: Any, parent: ET.Element):
        """Convert dictionary to XML"""
        if isinstance(data, dict):
            for key, value in data.items():
                child = ET.SubElement(parent, key)
                if isinstance(value, (dict, list)):
                    self._dict_to_xml(value, child)
                else:
                    child.text = str(value)
        elif isinstance(data, list):
            for item in data:
                self._dict_to_xml(item, parent)

if __name__ == "__main__":
    import uvicorn
    
    transformer = RequestTransformer()
    uvicorn.run(transformer.app, host="0.0.0.0", port=8000)