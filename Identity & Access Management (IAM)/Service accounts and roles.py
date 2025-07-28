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
        
    def remove_role(self, role_id: str):
        """Remove role from service account"""
        self.roles.discard(role_id)
        self.updated_at = datetime.now()
        
        def is_expired(self) -> bool:
            """Check if service account is expired"""
            if self.expires_at:
                return datetime.now() > self.expires_at 
            return False
        
    
    class TokenType(Enum):
        """Token types for different authentication methods"""
        JWT = "jwt"
        API_KEY = "api_key"
        CLIENT_CREDENTIALS = "client_credentials"
        
        
    @dataclass 
    class AccessToken:
        """Access token for autneticated requests"""
        token: str 
        token_type: TokenType 
        subject: str # User ID or Service Account ID 
        subject_type: str # "user" or "service_account"
        roles: Set[str]
        expires_at: datetime 
        issued_at: datetime = field(default_factory=datetime.now)
        scope: Optional[str] = None 
        
        
class RoleManager: 
    """Manages roles and permissions"""
    
    def __init__(self):
        self.roles: Dict[str, Role] = {}
        self._initiialize_system_roles()
        
    def _initialize_system_roles(self):
        """Create default system roles"""
        # Admin role - full access
        admin_role = Role(
            id="admin",
            name="Administrator",
            description="Full system access",
            is_system_role=True 
        )
        admin_role.add_permission(Permission(ResourceType.SYSTEM, "*", PermissionAction.ADMIN))
        admin_role.add_permission(Permission(ResourceType.USER, "*", PermissionAction.ADMIN))
        admin_role.add_permission(Permission(ResourceType.SERVICE, "*", PermissionAction.ADMIN))
        admin_role.add_permission(Permission(ResourceType.DATA, "*", PermissionAction.ADMIN))
        admin_role.add_permission(Permission(ResourceType.CONFIG, "*", PermissionAction.ADMIN))
        self.roles[admin_role.id] = admin_role 
        
        # Read-only role
        readonly_role = Role(
            id="readonly",
            name="Read Only",
            description="Read-only access to resources",
            is_system_role=True
        )
        readonly_role.add_permission(Permission(ResourceType.DATA, "*" PermissionAction.Read))
        readonly_role.add_permission(Permission(ResourceType.CONFIG, "*", PermissionAction.READ))
        self.role[readonly_role.id] = readonly_role 
        
        # Service role for API access 
        service_role = Role(
            id="service",
            name="Service",
            description="Service-to-service communication",
            is_system_role=True 
        )
        service_role.add_permission(Permission(ResourceType.SERVICE, "*", PermissionAction.READ))
        service_role.add_permission(Permission(ResourceType.DATA, "*", PermissionAction.READ))
        service_role.add_permission(Permission(ResourceType.DATA, "*", PermissionAction.WRITE))
        self.roles[service_role.id] = service_role 
        
    def create_role(self, name: str, description: str, permissions: List[Permission] = None) -> Role: 
        """Create a new role"""
        role_id = str(uuid.uuid4())
        role = Role(
            id=role_id,
            name=name,
            description=description
        )
        
        if permissions:
            for perm in permissions:
                role.add_permission(perm)
                
        self.roles[role_id] = role 
        return role 
    
    def get_role(self, role_id: str) -> Optional[Role]:
        """Get role by ID"""
        return self.roles.get(role_id)
    
    def delete_role(self, role_id: str) -> bool:
        """Delete role (cannot delete system roles)"""
        role = self.roles.get(role_id)
        if role and not role.is_system_role:
            del self.roles[role_id]
            return True 
        return False