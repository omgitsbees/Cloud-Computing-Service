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
const createAuthRateLimit = () => {
  const attempts = new Map();
  const maxAttempts = 5;
  const windowMs = 15 * 60 * 1000; // 15 minutes

  return (req, res, next) => {
    const key = req.ip + ':' + (req.body.email || req.body.username || 'unknown');
    const now = Date.now();
    
    if (!attempts.has(key)) {
      attempts.set(key, { count: 1, resetTime: now + windowMs });
      return next();
    }

    const attempt = attempts.get(key);
    
    if (now > attempt.resetTime) {
      attempt.count = 1;
      attempt.resetTime = now + windowMs;
      return next();
    }

    if (attempt.count >= maxAttempts) {
      return res.status(429).json({
        error: 'TooManyRequests',
        message: 'Too many authentication attempts. Please try again later.',
        retryAfter: Math.ceil((attempt.resetTime - now) / 1000)
      });
    }

    attempt.count++;
    next();
  };
};

module.exports = {
  TokenManager,
  RBACManager,
  OAuth2Server,
  authenticateToken,
  requirePermission,
  requireTenantAccess,
  createAuthRateLimit,
  AuthenticationError,
  AuthorizationError
};

// auth/routes.js
const express = require('express');
const bcrypt = require('bcryptjs');
const { body, validationResult } = require('express-validator');
const router = express.Router();

class AuthRoutes {
  constructor(tokenManager, rbacManager, oauth2Server) {
    this.tokenManager = tokenManager;
    this.rbacManager = rbacManager;
    this.oauth2Server = oauth2Server;
    this.users = new Map(); // In production, use database
    this.refreshTokens = new Set(); // In production, use Redis
  }

  setupRoutes() {
    // User Registration
    router.post('/register', [
      body('email').isEmail().normalizeEmail(),
      body('password').isLength({ min: 8 }).matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/),
      body('role').isIn(['admin', 'developer', 'viewer', 'billing_admin']),
      body('tenantId').notEmpty().trim()
    ], createAuthRateLimit(), async (req, res) => {
      try {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
          return res.status(400).json({
            error: 'ValidationError',
            message: 'Invalid input data',
            details: errors.array()
          });
        }

        const { email, password, role, tenantId, firstName, lastName } = req.body;

        // Check if user already exists
        if (this.users.has(email)) {
          return res.status(409).json({
            error: 'UserExists',
            message: 'User with this email already exists'
          });
        }

        // Validate role
        if (!this.rbacManager.validateRole(role)) {
          return res.status(400).json({
            error: 'InvalidRole',
            message: 'Invalid role specified'
          });
        }

        // Hash password
        const hashedPassword = await bcrypt.hash(password, 12);

        // Create user
        const user = {
          id: require('crypto').randomUUID(),
          email,
          password: hashedPassword,
          role,
          tenantId,
          firstName,
          lastName,
          permissions: this.rbacManager.getRolePermissions(role),
          createdAt: new Date(),
          isActive: true,
          lastLogin: null
        };

        this.users.set(email, user);

        // Generate tokens
        const tokens = this.tokenManager.generateTokenPair(user);
        this.refreshTokens.add(tokens.refreshToken);

        res.status(201).json({
          message: 'User registered successfully',
          user: {
            id: user.id,
            email: user.email,
            role: user.role,
            tenantId: user.tenantId,
            firstName: user.firstName,
            lastName: user.lastName,
            permissions: user.permissions
          },
          tokens
        });
      } catch (error) {
        console.error('Registration error:', error);
        res.status(500).json({
          error: 'InternalServerError',
          message: 'Registration failed'
        });
      }
    });

    // User Login
    router.post('/login', [
      body('email').isEmail().normalizeEmail(),
      body('password').notEmpty()
    ], createAuthRateLimit(), async (req, res) => {
      try {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
          return res.status(400).json({
            error: 'ValidationError',
            message: 'Invalid input data',
            details: errors.array()
          });
        }

        const { email, password } = req.body;
        const user = this.users.get(email);

        if (!user || !user.isActive) {
          return res.status(401).json({
            error: 'AuthenticationError',
            message: 'Invalid credentials'
          });
        }

        const isValidPassword = await bcrypt.compare(password, user.password);
        if (!isValidPassword) {
          return res.status(401).json({
            error: 'AuthenticationError',
            message: 'Invalid credentials'
          });
        }

        // Update last login
        user.lastLogin = new Date();

        // Generate tokens
        const tokens = this.tokenManager.generateTokenPair(user);
        this.refreshTokens.add(tokens.refreshToken);

        res.json({
          message: 'Login successful',
          user: {
            id: user.id,
            email: user.email,
            role: user.role,
            tenantId: user.tenantId,
            firstName: user.firstName,
            lastName: user.lastName,
            permissions: user.permissions,
            lastLogin: user.lastLogin
          },
          tokens
        });
      } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({
          error: 'InternalServerError',
          message: 'Login failed'
        });
      }
    });

    // Token Refresh
    router.post('/refresh', async (req, res) => {
      try {
        const { refreshToken } = req.body;
        
        if (!refreshToken || !this.refreshTokens.has(refreshToken)) {
          return res.status(401).json({
            error: 'AuthenticationError',
            message: 'Invalid refresh token'
          });
        }

        const decoded = await this.tokenManager.verifyRefreshToken(refreshToken);
        const user = Array.from(this.users.values()).find(u => u.id === decoded.userId);

        if (!user || !user.isActive) {
          this.refreshTokens.delete(refreshToken);
          return res.status(401).json({
            error: 'AuthenticationError',
            message: 'User not found or inactive'
          });
        }

        // Remove old refresh token and generate new tokens
        this.refreshTokens.delete(refreshToken);
        const tokens = this.tokenManager.generateTokenPair(user);
        this.refreshTokens.add(tokens.refreshToken);

        res.json({
          message: 'Token refreshed successfully',
          tokens
        });
      } catch (error) {
        console.error('Token refresh error:', error);
        res.status(401).json({
          error: 'AuthenticationError',
          message: 'Token refresh failed'
        });
      }
    });

    // Logout
    router.post('/logout', authenticateToken(this.tokenManager), (req, res) => {
      try {
        const { refreshToken } = req.body;
        if (refreshToken) {
          this.refreshTokens.delete(refreshToken);
        }

        res.json({
          message: 'Logout successful'
        });
      } catch (error) {
        console.error('Logout error:', error);
        res.status(500).json({
          error: 'InternalServerError',
          message: 'Logout failed'
        });
      }
    });

    // OAuth2 Authorization Endpoint
    router.get('/oauth/authorize', (req, res) => {
      try {
        const { client_id, redirect_uri, response_type, scope, state } = req.query;

        if (response_type !== 'code') {
          return res.status(400).json({
            error: 'unsupported_response_type',
            error_description: 'Only authorization code flow is supported'
          });
        }

        if (!client_id || !redirect_uri) {
          return res.status(400).json({
            error: 'invalid_request',
            error_description: 'Missing required parameters'
          });
        }

        // In a real app, this would render a consent page
        // For this example, we'll return the authorization URL
        const authUrl = `/auth/oauth/consent?client_id=${client_id}&redirect_uri=${encodeURIComponent(redirect_uri)}&scope=${scope || ''}&state=${state || ''}`;
        
        res.json({
          authorization_url: authUrl,
          client_id,
          redirect_uri,
          scope: scope || 'read',
          state
        });
      } catch (error) {
        console.error('OAuth authorization error:', error);
        res.status(500).json({
          error: 'server_error',
          error_description: 'Authorization failed'
        });
      }
    });

    // OAuth2 Token Endpoint
    router.post('/oauth/token', [
      body('grant_type').isIn(['authorization_code', 'refresh_token']),
      body('client_id').notEmpty(),
      body('client_secret').notEmpty()
    ], async (req, res) => {
      try {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
          return res.status(400).json({
            error: 'invalid_request',
            error_description: 'Invalid request parameters'
          });
        }

        const { grant_type, client_id, client_secret, code, redirect_uri } = req.body;

        if (grant_type === 'authorization_code') {
          const tokens = this.oauth2Server.exchangeCodeForTokens(
            code, client_id, client_secret, redirect_uri
          );

          res.json({
            access_token: tokens.accessToken,
            token_type: 'Bearer',
            expires_in: tokens.expiresIn,
            refresh_token: tokens.refreshToken
          });
        } else {
          res.status(400).json({
            error: 'unsupported_grant_type',
            error_description: 'Grant type not supported'
          });
        }
      } catch (error) {
        console.error('OAuth token error:', error);
        
        if (error instanceof AuthenticationError) {
          res.status(401).json({
            error: 'invalid_grant',
            error_description: error.message
          });
        } else {
          res.status(500).json({
            error: 'server_error',
            error_description: 'Token exchange failed'
          });
        }
      }
    });

    // Get Current User Profile
    router.get('/profile', authenticateToken(this.tokenManager), (req, res) => {
      try {
        const user = Array.from(this.users.values()).find(u => u.id === req.user.userId);
        
        if (!user) {
          return res.status(404).json({
            error: 'UserNotFound',
            message: 'User profile not found'
          });
        }

        res.json({
          user: {
            id: user.id,
            email: user.email,
            role: user.role,
            tenantId: user.tenantId,
            firstName: user.firstName,
            lastName: user.lastName,
            permissions: user.permissions,
            createdAt: user.createdAt,
            lastLogin: user.lastLogin
          }
        });
      } catch (error) {
        console.error('Profile fetch error:', error);
        res.status(500).json({
          error: 'InternalServerError',
          message: 'Failed to fetch profile'
        });
      }
    });

    return router;
  }
}

module.exports = AuthRoutes;

// Example usage in main app
/*
const express = require('express');
const { TokenManager, RBACManager, OAuth2Server } = require('./auth/middleware');
const AuthRoutes = require('./auth/routes');

const app = express();
app.use(express.json());

// Initialize authentication components
const tokenManager = new TokenManager(
  process.env.JWT_SECRET || 'your-jwt-secret',
  process.env.JWT_REFRESH_SECRET || 'your-refresh-secret'
);

const rbacManager = new RBACManager();
const oauth2Server = new OAuth2Server(tokenManager);

// Register OAuth2 client
oauth2Server.registerClient(
  'cloud-dashboard',
  'dashboard-secret',
  ['http://localhost:3000/callback'],
  ['read', 'write', 'admin']
);

// Setup auth routes
const authRoutes = new AuthRoutes(tokenManager, rbacManager, oauth2Server);
app.use('/auth', authRoutes.setupRoutes());

// Protected route examples
app.get('/api/resources', 
  authenticateToken(tokenManager),
  requirePermission(rbacManager, 'resources:read'),
  requireTenantAccess,
  (req, res) => {
    res.json({ message: 'Access granted to resources', user: req.user });
  }
);

app.post('/api/resources',
  authenticateToken(tokenManager),
  requirePermission(rbacManager, 'resources:write'),
  requireTenantAccess,
  (req, res) => {
    res.json({ message: 'Resource created', user: req.user });
  }
);

app.listen(3000, () => {
  console.log('Authentication server running on port 3000');
});
*/
