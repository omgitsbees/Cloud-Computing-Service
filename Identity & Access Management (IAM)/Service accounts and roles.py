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
      
    def list_roles(self) -> List[Role]:
        """List all roles"""
        return list(self.roles.values())


class ServiceAccountManager:
    """Manages service accounts"""
    
    def __init__(self, role_manager: RoleManager):
        self.service_accounts: Dict[str, ServiceAccount] = {}
        self.role_manager = role_manager
        self.client_id_to_account: Dict[str, str] = {}  # client_id -> account_id mapping
    
    def create_service_account(self, name: str, description: str, 
                             expires_in_days: Optional[int] = None) -> tuple[ServiceAccount, str]:
        """Create a new service account and return it with the client secret"""
        account_id = str(uuid.uuid4())
        client_id = f"sa_{secrets.token_urlsafe(16)}"
        client_secret = secrets.token_urlsafe(32)
        client_secret_hash = hashlib.sha256(client_secret.encode()).hexdigest()
        
        expires_at = None
        if expires_in_days:
            expires_at = datetime.now() + timedelta(days=expires_in_days)
        
        service_account = ServiceAccount(
            id=account_id,
            name=name,
            description=description,
            client_id=client_id,
            client_secret_hash=client_secret_hash,
            expires_at=expires_at,
            api_key=f"sk_{secrets.token_urlsafe(24)}"
        )
        
        self.service_accounts[account_id] = service_account
        self.client_id_to_account[client_id] = account_id
        
        return service_account, client_secret
    
    def get_service_account(self, account_id: str) -> Optional[ServiceAccount]:
        """Get service account by ID"""
        return self.service_accounts.get(account_id)
    
    def get_service_account_by_client_id(self, client_id: str) -> Optional[ServiceAccount]:
        """Get service account by client ID"""
        account_id = self.client_id_to_account.get(client_id)
        return self.service_accounts.get(account_id) if account_id else None
    
    def authenticate_service_account(self, client_id: str, client_secret: str) -> Optional[ServiceAccount]:
        """Authenticate service account with client credentials"""
        account = self.get_service_account_by_client_id(client_id)
        
        if not account:
            return None
        
        if not account.is_active or account.is_expired():
            return None
        
        # Verify client secret
        secret_hash = hashlib.sha256(client_secret.encode()).hexdigest()
        if secret_hash != account.client_secret_hash:
            return None
        
        # Update last used timestamp
        account.last_used = datetime.now()
        return account
    
    def authenticate_api_key(self, api_key: str) -> Optional[ServiceAccount]:
        """Authenticate service account with API key"""
        for account in self.service_accounts.values():
            if account.api_key == api_key and account.is_active and not account.is_expired():
                account.last_used = datetime.now()
                return account
        return None
    
    def assign_role_to_service_account(self, account_id: str, role_id: str) -> bool:
        """Assign role to service account"""
        account = self.get_service_account(account_id)
        role = self.role_manager.get_role(role_id)
        
        if account and role:
            account.add_role(role_id)
            return True
        return False
    
    def revoke_role_from_service_account(self, account_id: str, role_id: str) -> bool:
        """Revoke role from service account"""
        account = self.get_service_account(account_id)
        if account:
            account.remove_role(role_id)
            return True
        return False
    
    def deactivate_service_account(self, account_id: str) -> bool:
        """Deactivate service account"""
        account = self.get_service_account(account_id)
        if account:
            account.is_active = False
            account.updated_at = datetime.now()
            return True
        return False
    
    def list_service_accounts(self) -> List[ServiceAccount]:
        """List all service accounts"""
        return list(self.service_accounts.values())


class TokenManager:
    """Manages access tokens"""
    
    def __init__(self, role_manager: RoleManager):
        self.role_manager = role_manager
        self.active_tokens: Dict[str, AccessToken] = {}
        
        # Generate RSA key pair for JWT signing
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        self.public_key = self.private_key.public_key()
    
    def create_jwt_token(self, subject: str, subject_type: str, roles: Set[str], 
                        expires_in_seconds: int = 3600) -> AccessToken:
        """Create JWT access token"""
        now = datetime.now()
        expires_at = now + timedelta(seconds=expires_in_seconds)
        
        payload = {
            'sub': subject,
            'sub_type': subject_type,
            'roles': list(roles),
            'iat': int(now.timestamp()),
            'exp': int(expires_at.timestamp()),
            'jti': str(uuid.uuid4())
        }
        
        # Sign JWT with private key
        private_pem = self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        token = jwt.encode(payload, private_pem, algorithm='RS256')
        
        access_token = AccessToken(
            token=token,
            token_type=TokenType.JWT,
            subject=subject,
            subject_type=subject_type,
            roles=roles,
            expires_at=expires_at
        )
        
        self.active_tokens[payload['jti']] = access_token
        return access_token
    
    def verify_jwt_token(self, token: str) -> Optional[AccessToken]:
        """Verify and decode JWT token"""
        try:
            public_pem = self.public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            
            payload = jwt.decode(token, public_pem, algorithms=['RS256'])
            
            # Check if token is still active
            jti = payload.get('jti')
            if jti not in self.active_tokens:
                return None
            
            access_token = self.active_tokens[jti]
            
            # Check expiration
            if datetime.now() > access_token.expires_at:
                del self.active_tokens[jti]
                return None
            
            return access_token
            
        except jwt.InvalidTokenError:
            return None
    
    def revoke_token(self, token: str) -> bool:
        """Revoke access token"""
        try:
            public_pem = self.public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            
            payload = jwt.decode(token, public_pem, algorithms=['RS256'], options={"verify_exp": False})
            jti = payload.get('jti')
            
            if jti in self.active_tokens:
                del self.active_tokens[jti]
                return True
                
        except jwt.InvalidTokenError:
            pass
        
        return False


class AccessControlManager:
    """Main access control manager combining all components"""
    
    def __init__(self):
        self.role_manager = RoleManager()
        self.service_account_manager = ServiceAccountManager(self.role_manager)
        self.token_manager = TokenManager(self.role_manager)
    
    def check_permission(self, subject: str, subject_type: str, 
                        resource_type: ResourceType, resource_id: str, 
                        action: PermissionAction) -> bool:
        """Check if subject has permission for action on resource"""
        
        # Get subject's roles
        roles = set()
        if subject_type == "service_account":
            account = self.service_account_manager.get_service_account(subject)
            if account:
                roles = account.roles
        # Add user role checking here when integrating with user management
        
        # Check permissions across all roles
        for role_id in roles:
            role = self.role_manager.get_role(role_id)
            if role and role.has_permission(resource_type, resource_id, action):
                return True
        
        return False
    
    def authenticate_and_authorize(self, auth_header: str) -> Optional[AccessToken]:
        """Authenticate request and return access token if valid"""
        if not auth_header:
            return None
        
        # Handle Bearer token (JWT)
        if auth_header.startswith("Bearer "):
            token = auth_header[7:]
            return self.token_manager.verify_jwt_token(token)
        
        # Handle API Key
        elif auth_header.startswith("ApiKey "):
            api_key = auth_header[7:]
            account = self.service_account_manager.authenticate_api_key(api_key)
            if account:
                # Create temporary token for this request
                return AccessToken(
                    token=api_key,
                    token_type=TokenType.API_KEY,
                    subject=account.id,
                    subject_type="service_account",
                    roles=account.roles,
                    expires_at=datetime.now() + timedelta(hours=1)
                )
        
        return None


# Example usage and testing
if __name__ == "__main__":
    # Initialize the access control system
    acm = AccessControlManager()
    
    print("=== Service Accounts and Roles Management System ===\n")
    
    # 1. Create custom roles
    print("1. Creating custom roles...")
    
    # Data analyst role
    data_permissions = [
        Permission(ResourceType.DATA, "*", PermissionAction.READ),
        Permission(ResourceType.DATA, "analytics_*", PermissionAction.WRITE)
    ]
    analyst_role = acm.role_manager.create_role(
        "Data Analyst", 
        "Can read all data and write to analytics datasets",
        data_permissions
    )
    print(f"Created role: {analyst_role.name} ({analyst_role.id})")
    
    # API service role
    api_permissions = [
        Permission(ResourceType.SERVICE, "*", PermissionAction.READ),
        Permission(ResourceType.DATA, "public_*", PermissionAction.READ)
    ]
    api_role = acm.role_manager.create_role(
        "API Service",
        "Public API access role",
