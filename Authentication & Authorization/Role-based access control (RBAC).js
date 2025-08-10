// ================================
// RBAC System Implementation
// ================================

// Core RBAC Models
class Permission {
  constructor(name, resource, action, description = '') {
    this.name = name;
    this.resource = resource;
    this.action = action;
    this.description = description;
    this.createdAt = new Date();
  }
}

class Role {
  constructor(name, description = '') {
    this.name = name;
    this.description = description;
    this.permissions = new Set();
    this.createdAt = new Date();
    this.updatedAt = new Date();
  }

  addPermission(permission) {
    this.permissions.add(permission);
    this.updatedAt = new Date();
  }

  removePermission(permission) {
    this.permissions.delete(permission);
    this.updatedAt = new Date();
  }

  hasPermission(permissionName) {
    return Array.from(this.permissions).some(p => p.name === permissionName);
  }
}

class User {
  constructor(id, email, name) {
    this.id = id;
    this.email = email;
    this.name = name;
    this.roles = new Set();
    this.directPermissions = new Set();
    this.createdAt = new Date();
    this.updatedAt = new Date();
  }

  assignRole(role) {
    this.roles.add(role);
    this.updatedAt = new Date();
  }

  removeRole(role) {
    this.roles.delete(role);
    this.updatedAt = new Date();
  }

  grantPermission(permission) {
    this.directPermissions.add(permission);
    this.updatedAt = new Date();
  }

  revokePermission(permission) {
    this.directPermissions.delete(permission);
    this.updatedAt = new Date();
  }

  getAllPermissions() {
    const allPermissions = new Set(this.directPermissions);
    
    // Add permissions from all roles
    this.roles.forEach(role => {
      role.permissions.forEach(permission => {
        allPermissions.add(permission);
      });
    });

    return allPermissions;
  }

  hasPermission(permissionName) {
    // Check direct permissions
    if (Array.from(this.directPermissions).some(p => p.name === permissionName)) {
      return true;
    }

    // Check role-based permissions
    return Array.from(this.roles).some(role => role.hasPermission(permissionName));
  }

  canAccess(resource, action) {
    const allPermissions = this.getAllPermissions();
    return Array.from(allPermissions).some(p => 
      p.resource === resource && p.action === action
    );
  }
}

// ================================
// RBAC Manager
// ================================

class RBACManager {
  constructor() {
    this.users = new Map();
    this.roles = new Map();
    this.permissions = new Map();
    this.initializeDefaultRolesAndPermissions();
  }

  // Initialize default roles and permissions for cloud platform
  initializeDefaultRolesAndPermissions() {
    // Define common permissions
    const permissions = [
      // User management
      new Permission('user.read', 'user', 'read', 'View user information'),
      new Permission('user.create', 'user', 'create', 'Create new users'),
      new Permission('user.update', 'user', 'update', 'Update user information'),
      new Permission('user.delete', 'user', 'delete', 'Delete users'),
      
      // Resource management
      new Permission('resource.read', 'resource', 'read', 'View resources'),
      new Permission('resource.create', 'resource', 'create', 'Create resources'),
      new Permission('resource.update', 'resource', 'update', 'Update resources'),
      new Permission('resource.delete', 'resource', 'delete', 'Delete resources'),
      
      // Billing and subscription
      new Permission('billing.read', 'billing', 'read', 'View billing information'),
      new Permission('billing.manage', 'billing', 'manage', 'Manage billing and payments'),
      
      // Analytics and monitoring
      new Permission('analytics.read', 'analytics', 'read', 'View analytics data'),
      new Permission('monitoring.read', 'monitoring', 'read', 'View monitoring data'),
      
      // Security and audit
      new Permission('audit.read', 'audit', 'read', 'View audit logs'),
      new Permission('security.manage', 'security', 'manage', 'Manage security settings'),
      
      // Role management
      new Permission('role.read', 'role', 'read', 'View roles'),
      new Permission('role.manage', 'role', 'manage', 'Manage roles and permissions'),
      
      // System administration
      new Permission('system.admin', 'system', 'admin', 'Full system administration')
    ];

    permissions.forEach(p => this.permissions.set(p.name, p));

    // Define default roles
    const roles = [
      { name: 'viewer', perms: ['user.read', 'resource.read', 'analytics.read', 'monitoring.read'] },
      { name: 'editor', perms: ['user.read', 'resource.read', 'resource.create', 'resource.update'] },
      { name: 'admin', perms: ['user.read', 'user.create', 'user.update', 'resource.read', 'resource.create', 'resource.update', 'resource.delete', 'billing.read', 'analytics.read', 'monitoring.read', 'audit.read'] },
      { name: 'owner', perms: Array.from(this.permissions.keys()) },
      { name: 'billing_manager', perms: ['user.read', 'billing.read', 'billing.manage', 'analytics.read'] },
      { name: 'security_officer', perms: ['user.read', 'audit.read', 'security.manage', 'monitoring.read'] }
    ];

    roles.forEach(roleData => {
      const role = new Role(roleData.name, `Default ${roleData.name} role`);
      roleData.perms.forEach(permName => {
        if (this.permissions.has(permName)) {
          role.addPermission(this.permissions.get(permName));
        }
      });
      this.roles.set(role.name, role);
    });
  }

  // User management
  createUser(id, email, name) {
    const user = new User(id, email, name);
    this.users.set(id, user);
    return user;
  }

  getUser(userId) {
    return this.users.get(userId);
  }

  // Role management
  createRole(name, description = '') {
    if (this.roles.has(name)) {
      throw new Error(`Role '${name}' already exists`);
    }
    const role = new Role(name, description);
    this.roles.set(name, role);
    return role;
  }

  getRole(roleName) {
    return this.roles.get(roleName);
  }

  getAllRoles() {
    return Array.from(this.roles.values());
  }

  // Permission management
  createPermission(name, resource, action, description = '') {
    if (this.permissions.has(name)) {
      throw new Error(`Permission '${name}' already exists`);
    }
    const permission = new Permission(name, resource, action, description);
    this.permissions.set(name, permission);
    return permission;
  }

  getPermission(permissionName) {
    return this.permissions.get(permissionName);
  }

  getAllPermissions() {
    return Array.from(this.permissions.values());
  }

  // User-Role assignment
  assignRoleToUser(userId, roleName) {
    const user = this.getUser(userId);
    const role = this.getRole(roleName);
    
    if (!user) throw new Error(`User with ID '${userId}' not found`);
    if (!role) throw new Error(`Role '${roleName}' not found`);
    
    user.assignRole(role);
    return user;
  }

  removeRoleFromUser(userId, roleName) {
    const user = this.getUser(userId);
    const role = this.getRole(roleName);
    
    if (!user) throw new Error(`User with ID '${userId}' not found`);
    if (!role) throw new Error(`Role '${roleName}' not found`);
    
    user.removeRole(role);
    return user;
  }

  // Direct permission assignment
  grantPermissionToUser(userId, permissionName) {
    const user = this.getUser(userId);
    const permission = this.getPermission(permissionName);
    
    if (!user) throw new Error(`User with ID '${userId}' not found`);
    if (!permission) throw new Error(`Permission '${permissionName}' not found`);
    
    user.grantPermission(permission);
    return user;
  }

  // Authorization check
  checkPermission(userId, permissionName) {
    const user = this.getUser(userId);
    if (!user) return false;
    
    return user.hasPermission(permissionName);
  }

  checkAccess(userId, resource, action) {
    const user = this.getUser(userId);
    if (!user) return false;
    
    return user.canAccess(resource, action);
  }

  // Get user's effective permissions
  getUserPermissions(userId) {
    const user = this.getUser(userId);
    if (!user) return [];
    
    return Array.from(user.getAllPermissions());
  }

  // Audit functions
  getUserRoles(userId) {
    const user = this.getUser(userId);
    if (!user) return [];
    
    return Array.from(user.roles).map(role => ({
      name: role.name,
      description: role.description,
      permissions: Array.from(role.permissions)
    }));
  }

  getRoleUsers(roleName) {
    const role = this.getRole(roleName);
    if (!role) return [];
    
    return Array.from(this.users.values())
      .filter(user => user.roles.has(role))
      .map(user => ({ id: user.id, email: user.email, name: user.name }));
  }
}

// ================================
// Express.js Middleware for RBAC
// ================================

class RBACMiddleware {
  constructor(rbacManager) {
    this.rbacManager = rbacManager;
  }

  // Middleware to check if user has specific permission
  requirePermission(permissionName) {
    return (req, res, next) => {
      try {
        const userId = req.user?.id; // Assumes JWT middleware has populated req.user
        
        if (!userId) {
          return res.status(401).json({ error: 'Authentication required' });
        }

        if (this.rbacManager.checkPermission(userId, permissionName)) {
          next();
        } else {
          res.status(403).json({ 
            error: 'Insufficient permissions',
            required: permissionName 
          });
        }
      } catch (error) {
        res.status(500).json({ error: 'Authorization check failed' });
      }
    };
  }

  // Middleware to check if user has specific role
  requireRole(roleName) {
    return (req, res, next) => {
      try {
        const userId = req.user?.id;
        
        if (!userId) {
          return res.status(401).json({ error: 'Authentication required' });
        }

        const user = this.rbacManager.getUser(userId);
        if (user && Array.from(user.roles).some(role => role.name === roleName)) {
          next();
        } else {
          res.status(403).json({ 
            error: 'Insufficient role',
            required: roleName 
          });
        }
      } catch (error) {
        res.status(500).json({ error: 'Authorization check failed' });
      }
    };
  }

  // Middleware to check resource access
  requireAccess(resource, action) {
    return (req, res, next) => {
      try {
        const userId = req.user?.id;
        
        if (!userId) {
          return res.status(401).json({ error: 'Authentication required' });
        }

        if (this.rbacManager.checkAccess(userId, resource, action)) {
          next();
        } else {
          res.status(403).json({ 
            error: 'Access denied',
            resource,
            action 
          });
        }
      } catch (error) {
        res.status(500).json({ error: 'Authorization check failed' });
      }
    };
  }

  // Middleware to attach user permissions to request
  attachUserPermissions() {
    return (req, res, next) => {
      try {
        const userId = req.user?.id;
        
        if (userId) {
          req.userPermissions = this.rbacManager.getUserPermissions(userId);
          req.userRoles = this.rbacManager.getUserRoles(userId);
        }
        
        next();
      } catch (error) {
        next(); // Continue without permissions if there's an error
      }
    };
  }
}

// ================================
// Example Usage and Routes
// ================================

// Initialize RBAC system
const rbacManager = new RBACManager();
const rbacMiddleware = new RBACMiddleware(rbacManager);

// Example: Create a user and assign roles
const exampleUser = rbacManager.createUser('user123', 'john@example.com', 'John Doe');
rbacManager.assignRoleToUser('user123', 'admin');

console.log('RBAC System initialized successfully!');
console.log('Available roles:', rbacManager.getAllRoles().map(r => r.name));
console.log('User permissions:', rbacManager.getUserPermissions('user123').map(p => p.name));

// Export for use in your application
module.exports = {
  RBACManager,
  RBACMiddleware,
  Permission,
  Role,
  User,
  rbacManager, // Pre-configured instance
  rbacMiddleware // Pre-configured middleware
};

// ================================
// Example Express Routes with RBAC
// ================================

/*
// In your Express app:
const express = require('express');
const { rbacMiddleware } = require('./rbac-system');

const app = express();

// User management routes
app.get('/api/users', 
  rbacMiddleware.requirePermission('user.read'), 
  (req, res) => {
    res.json({ users: [] });
  }
);

app.post('/api/users', 
  rbacMiddleware.requirePermission('user.create'), 
  (req, res) => {
    res.json({ message: 'User created' });
  }
);

// Resource management routes
app.get('/api/resources', 
  rbacMiddleware.requireAccess('resource', 'read'), 
  (req, res) => {
    res.json({ resources: [] });
  }
);

app.delete('/api/resources/:id', 
  rbacMiddleware.requireRole('admin'), 
  (req, res) => {
    res.json({ message: 'Resource deleted' });
  }
);

// Billing routes (restricted to billing managers and owners)
app.get('/api/billing', 
  rbacMiddleware.requirePermission('billing.read'), 
  (req, res) => {
    res.json({ billing: {} });
  }
);

// Admin routes
app.get('/api/admin/audit', 
  rbacMiddleware.requirePermission('audit.read'), 
  (req, res) => {
    res.json({ auditLogs: [] });
  }
);
*/