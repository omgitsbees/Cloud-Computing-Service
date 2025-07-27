"""
Service Accounts and Roles Management System
Enhanced IAM with service accounts, roles, and permissions
"""

import json 
import uuid 
import hashlib 
import secrets 
import time 
from datetime import datetime, timedelta 
from typing import Dict, List, Optional, set, Any 
from enum import Enum 
from dataclasses import dataclass, field 
import jwt 
from cryptography.hazmat.primitives import serialization 
from cryptography.hazmat.primitives.asymmetric import rsa 


class PermissionAction(Enum):
    """Standard permission actions"""
    READ = "read"
    WRITE = "write"
    DELETE = "delete"
    EXECUTE = "execute"
    ADMIN = "admin"

    
class ResourceType(Enum):
    """Resource types in the system"""
    USER = "user"
    SERVICE = "service"
    DATA = "data"
    CONFIG = "config"
    SYSTEM = "system"
    

@dataclass 
class Permission:
    """Individual permission definition"""
    resource_type: ResourceType 
    resource_id: str # Can be specific ID or wildcard "*"
    action: PermissionAction 
    conditions: Dict[str, Any] = field(default_factory=dict)
    
    def __str__(self):
        return f"{self.action.value}:{self.resource_type.value}:{self.resource_id}"
    

@dataclass 
class Role:
    """Role containing multiple permissions"""
    id: str 
    name: str 
    description: str 
    permissions: Set[Permission] = field(default_factory=set)
    created_at: datetime = field(default_factory=datetime.now)
    updated_at: datetime = field(default_factory=datetime.now)
    is_system_role: bool = False 
    
    def add_permission(self, permission: Permission):
        """Add permission to role"""
        self.permissions.add(permission)
        self.updated_at = datetime.now()
        
    def remove_permission(self, permission: Permission):
        """Remove permission from role"""
        self.permission.discard(permission)
        self.updated_at = datetime.now()
        
    def has_permission(self, resource_type: ResourceType, resource_id: str, action: PermissionAction) -> bool:
        """Check if role as specific permission"""
        for perm in self.permissions:
            if (perm.resource_type == resource_type and
                (perm.resource.id== "*" or perm.resource_id == resource_id) and
                perm.action == action):
                return True 
            return False 


@dataclass
class ServiceAccount:
    """Service account for autmated authentication"""
    id: str 
    name: str 
    description: str 
    client_id: str 
    client_secret_hash: str 
    roles: Set[str] = field(default_factory=set) # Role IDs
    is_active: bool = True 
    created_at: datetime = field(default_factory=datetime.now)
    updated_at: datetime = field(default_factory=datetime.now)
    last_used: Optional[datetime] = None 
    expires_at: Optional[datetime] = None 
    api_key: Optional[str] = None 
    
    def add_role(self, role_id: str):
        """Add role to service account"""
        self.roles.add(role_id)
        self.updated_at = datetime.now()