// auth/middleware.js
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const { promisify } = require('util');

class AuthenticationError extends Error {
  constructor(message) {
    super(message);
    this.name = 'AuthenticationError';
    this.statusCode = 401;
  }
}

class AuthorizationError extends Error {
  constructor(message) {
    super(message);
    this.name = 'AuthorizationError';
    this.statusCode = 403;
  }
}

// JWT Token Manager
class TokenManager {
  constructor(secret, refreshSecret) {
    this.secret = secret;
    this.refreshSecret = refreshSecret;
    this.accessTokenExpiry = '15m';
    this.refreshTokenExpiry = '7d';
  }

  generateAccessToken(payload) {
    return jwt.sign(payload, this.secret, { 
      expiresIn: this.accessTokenExpiry,
      issuer: 'aws-cloud-service',
      audience: 'cloud-users'
    });
  }

  generateRefreshToken(payload) {
    return jwt.sign(payload, this.refreshSecret, { 
      expiresIn: this.refreshTokenExpiry,
      issuer: 'aws-cloud-service',
      audience: 'cloud-users'
    });
  }

  async verifyAccessToken(token) {
    try {
      return jwt.verify(token, this.secret);
    } catch (error) {
      throw new AuthenticationError('Invalid or expired access token');
    }
  }

  async verifyRefreshToken(token) {
    try {
      return jwt.verify(token, this.refreshSecret);
    } catch (error) {
      throw new AuthenticationError('Invalid or expired refresh token');
    }
  }

  generateTokenPair(user) {
    const payload = {
      userId: user.id,
      email: user.email,
      role: user.role,
      permissions: user.permissions,
      tenantId: user.tenantId
    };

    return {
      accessToken: this.generateAccessToken(payload),
      refreshToken: this.generateRefreshToken({ userId: user.id }),
      expiresIn: 900 // 15 minutes in seconds
    };
  }
}

// Role-Based Access Control
class RBACManager {
  constructor() {
    this.roles = {
      'super_admin': {
        permissions: ['*'],
        description: 'Full system access'
      },
      'admin': {
        permissions: [
          'users:read', 'users:write', 'users:delete',
          'resources:read', 'resources:write', 'resources:delete',
          'billing:read', 'billing:write',
          'audit:read'
        ],
        description: 'Administrative access within tenant'
      },
      'developer': {
        permissions: [
          'resources:read', 'resources:write',

          'deployments:read', 'deployments:write',
          'logs:read', 'monitoring:read'
        ],
        description: 'Development and deployment access'
      },
      'viewer': {
        permissions: [
          'resources:read', 'logs:read', 'monitoring:read'
        ],
        description: 'Read-only access'
      },
      'billing_admin': {
        permissions: [
          'billing:read', 'billing:write',
          'resources:read', 'usage:read'
        ],
        description: 'Billing and usage management'
      }
    };
  }

  hasPermission(userRole, userPermissions, requiredPermission) {
    // Super admin has all permissions
    if (userRole === 'super_admin') return true;

    // Check if user has wildcard permission
    if (userPermissions.includes('*')) return true;

    // Check specific permission
    if (userPermissions.includes(requiredPermission)) return true;

    // Check wildcard resource permissions (e.g., 'resources:*' for 'resources:read')
    const [resource, action] = requiredPermission.split(':');
    if (userPermissions.includes(`${resource}:*`)) return true;

    return false;
  }

  getRolePermissions(role) {
    return this.roles[role]?.permissions || [];
  }

  validateRole(role) {
    return Object.keys(this.roles).includes(role);
  }
}

// OAuth2 Authorization Server
class OAuth2Server {
  constructor(tokenManager) {
    this.tokenManager = tokenManager;
    this.authorizationCodes = new Map(); // In production, use Redis
    this.clients = new Map(); // In production, use database
    this.codeExpiry = 10 * 60 * 1000; // 10 minutes
  }

  registerClient(clientId, clientSecret, redirectUris, scopes) {
    this.clients.set(clientId, {
      clientSecret: bcrypt.hashSync(clientSecret, 10),
      redirectUris,
      scopes,
      createdAt: new Date()
    });
  }

  validateClient(clientId, clientSecret) {
    const client = this.clients.get(clientId);
    if (!client) return false;
    return bcrypt.compareSync(clientSecret, client.clientSecret);
  }

  generateAuthorizationCode(clientId, userId, redirectUri, scopes) {
    const code = require('crypto').randomBytes(32).toString('hex');
    this.authorizationCodes.set(code, {
      clientId,
      userId,
      redirectUri,
      scopes,
      expiresAt: Date.now() + this.codeExpiry
    });
    
    // Clean up expired codes
    setTimeout(() => this.authorizationCodes.delete(code), this.codeExpiry);
    
    return code;
  }

  exchangeCodeForTokens(code, clientId, clientSecret, redirectUri) {
    const authCode = this.authorizationCodes.get(code);
    
    if (!authCode) {
      throw new AuthenticationError('Invalid authorization code');
    }

    if (authCode.expiresAt < Date.now()) {
      this.authorizationCodes.delete(code);
      throw new AuthenticationError('Authorization code expired');
    }
    if (authCode.clientId !== clientId || authCode.redirectUri !== redirectUri) {
      throw new AuthenticationError('Invalid client or redirect URI');          
    }

    if (!this.validateClient(clientId, clientSecret)) {
      throw new AuthenticationError('Invalid client credentials');
    }

    // Delete the code after use
    this.authorizationCodes.delete(code);

    // Generate tokens (this would normally fetch user from database)
    const user = { 
      id: authCode.userId, 
      role: 'developer', 
      permissions: ['resources:read', 'resources:write'] 
    };
    
    return this.tokenManager.generateTokenPair(user);
  }
}

// Authentication Middleware
const authenticateToken = (tokenManager) => {
  return async (req, res, next) => {
    try {
      const authHeader = req.headers.authorization;
      if (!authHeader || !authHeader.startsWith('Bearer ')) {
        throw new AuthenticationError('Missing or invalid authorization header');
      }

      const token = authHeader.substring(7);
      const decoded = await tokenManager.verifyAccessToken(token);
      
      req.user = decoded;
      next();
    } catch (error) {
      res.status(error.statusCode || 401).json({
        error: error.name,
        message: error.message
      });
    }
  };
};

// Authorization Middleware
const requirePermission = (rbacManager, permission) => {
  return (req, res, next) => {
    try {
      if (!req.user) {
        throw new AuthenticationError('User not authenticated');
      }

      const hasPermission = rbacManager.hasPermission(
        req.user.role,
        req.user.permissions,
        permission
      );

      if (!hasPermission) {
        throw new AuthorizationError(`Insufficient permissions. Required: ${permission}`);
      }

      next();
    } catch (error) {
      res.status(error.statusCode || 403).json({
        error: error.name,
        message: error.message
      });
    }
  };
};

// Multi-tenant Authorization
const requireTenantAccess = (req, res, next) => {
  try {
    const requestedTenantId = req.params.tenantId || req.body.tenantId || req.query.tenantId;
    
    if (!requestedTenantId) {
      throw new AuthorizationError('Tenant ID required');
    }

    // Super admins can access any tenant
    if (req.user.role === 'super_admin') {
      return next();
    }

    // Users can only access their own tenant
    if (req.user.tenantId !== requestedTenantId) {
      throw new AuthorizationError('Access denied to tenant resources');
    }

    next();
  } catch (error) {
    res.status(error.statusCode || 403).json({
      error: error.name,
      message: error.message
    });
  }
};

// Rate limiting for auth endpoints
