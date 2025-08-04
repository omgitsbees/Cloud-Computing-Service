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