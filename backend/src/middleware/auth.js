/**
 * Authentication Middleware
 * Handles JWT token verification, user authentication, and role-based access control
 */

const jwt = require('jsonwebtoken');
const User = require('../models/User');
const logger = require('../config/logger');
const { cache } = require('../config/redis');

/**
 * Verify JWT token and authenticate user
 * @param {Object} req - Express request object
 * @param {Object} res - Express response object
 * @param {Function} next - Express next function
 */
const authenticate = async (req, res, next) => {
  try {
    // Get token from header
    const authHeader = req.header('Authorization');
    
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      logger.security('Authentication failed: No token provided', {
        ip: req.ip,
        userAgent: req.get('User-Agent'),
        url: req.originalUrl
      });
      
      return res.status(401).json({
        success: false,
        message: 'Access denied. No token provided.'
      });
    }

    const token = authHeader.replace('Bearer ', '');

    // Check if token is blacklisted
    const isBlacklisted = await cache.get(`blacklist:${token}`);
    if (isBlacklisted) {
      logger.security('Authentication failed: Token blacklisted', {
        ip: req.ip,
        userAgent: req.get('User-Agent'),
        url: req.originalUrl
      });
      
      return res.status(401).json({
        success: false,
        message: 'Token is invalid.'
      });
    }

    // Verify token
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    
    // Check if user exists and is active
    const user = await User.findById(decoded.id)
      .select('-password')
      .populate('organization', 'name plan status');

    if (!user) {
      logger.security('Authentication failed: User not found', {
        userId: decoded.id,
        ip: req.ip,
        userAgent: req.get('User-Agent'),
        url: req.originalUrl
      });
      
      return res.status(401).json({
        success: false,
        message: 'User not found.'
      });
    }

    if (!user.isActive) {
      logger.security('Authentication failed: User inactive', {
        userId: user._id,
        ip: req.ip,
        userAgent: req.get('User-Agent'),
        url: req.originalUrl
      });
      
      return res.status(401).json({
        success: false,
        message: 'Account is deactivated.'
      });
    }

    // Check if organization is active (for SaaS multi-tenancy)
    if (user.organization && user.organization.status !== 'active') {
      logger.security('Authentication failed: Organization inactive', {
        userId: user._id,
        organizationId: user.organization._id,
        ip: req.ip,
        url: req.originalUrl
      });
      
      return res.status(403).json({
        success: false,
        message: 'Organization account is suspended.'
      });
    }

    // Update last activity
    user.lastActivity = new Date();
    await user.save();

    // Add user to request object
    req.user = user;
    req.token = token;

    logger.debug('User authenticated successfully', {
      userId: user._id,
      email: user.email,
      role: user.role,
      ip: req.ip
    });

    next();
  } catch (error) {
    if (error.name === 'JsonWebTokenError') {
      logger.security('Authentication failed: Invalid token', {
        error: error.message,
        ip: req.ip,
        userAgent: req.get('User-Agent'),
        url: req.originalUrl
      });
      
      return res.status(401).json({
        success: false,
        message: 'Invalid token.'
      });
    }
    
    if (error.name === 'TokenExpiredError') {
      logger.security('Authentication failed: Token expired', {
        ip: req.ip,
        userAgent: req.get('User-Agent'),
        url: req.originalUrl
      });
      
      return res.status(401).json({
        success: false,
        message: 'Token expired.'
      });
    }

    logger.error('Authentication middleware error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error during authentication.'
    });
  }
};

/**
 * Role-based authorization middleware
 * @param {Array} roles - Allowed roles
 * @returns {Function} Middleware function
 */
const authorize = (...roles) => {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({
        success: false,
        message: 'Access denied. Authentication required.'
      });
    }

    if (!roles.includes(req.user.role)) {
      logger.security('Authorization failed: Insufficient permissions', {
        userId: req.user._id,
        userRole: req.user.role,
        requiredRoles: roles,
        ip: req.ip,
        url: req.originalUrl
      });
      
      return res.status(403).json({
        success: false,
        message: 'Access denied. Insufficient permissions.'
      });
    }

    logger.debug('User authorized successfully', {
      userId: req.user._id,
      role: req.user.role,
      allowedRoles: roles
    });

    next();
  };
};

/**
 * Organization access control middleware
 * Ensures user can only access resources from their organization
 * @param {Object} req - Express request object
 * @param {Object} res - Express response object
 * @param {Function} next - Express next function
 */
const checkOrganizationAccess = async (req, res, next) => {
  try {
    // Super admin can access all organizations
    if (req.user.role === 'super_admin') {
      return next();
    }

    // Check if organization ID is provided in request
    const organizationId = req.params.organizationId || 
                          req.body.organizationId || 
                          req.query.organizationId ||
                          req.user.organization?._id;

    if (!organizationId) {
      return res.status(400).json({
        success: false,
        message: 'Organization ID is required.'
      });
    }

    // Check if user belongs to the organization
    if (req.user.organization?._id.toString() !== organizationId.toString()) {
      logger.security('Organization access denied', {
        userId: req.user._id,
        userOrganization: req.user.organization?._id,
        requestedOrganization: organizationId,
        ip: req.ip,
        url: req.originalUrl
      });
      
      return res.status(403).json({
        success: false,
        message: 'Access denied. You can only access your organization resources.'
      });
    }

    next();
  } catch (error) {
    logger.error('Organization access control error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error during organization access control.'
    });
  }
};

/**
 * API rate limiting for authenticated users
 * @param {number} maxRequests - Maximum requests per window
 * @param {number} windowMs - Time window in milliseconds
 * @returns {Function} Middleware function
 */
const userRateLimit = (maxRequests = 1000, windowMs = 15 * 60 * 1000) => {
  return async (req, res, next) => {
    try {
      if (!req.user) {
        return next();
      }

      const key = `rate_limit:${req.user._id}`;
      const current = await cache.get(key) || 0;

      if (current >= maxRequests) {
        logger.security('Rate limit exceeded', {
          userId: req.user._id,
          current,
          limit: maxRequests,
          ip: req.ip,
          url: req.originalUrl
        });
        
        return res.status(429).json({
          success: false,
          message: 'Rate limit exceeded. Please try again later.',
          retryAfter: Math.ceil(windowMs / 1000)
        });
      }

      // Increment counter
      await cache.set(key, current + 1, Math.ceil(windowMs / 1000));

      // Add rate limit headers
      res.set({
        'X-RateLimit-Limit': maxRequests,
        'X-RateLimit-Remaining': Math.max(0, maxRequests - current - 1),
        'X-RateLimit-Reset': new Date(Date.now() + windowMs).toISOString()
      });

      next();
    } catch (error) {
      logger.error('User rate limiting error:', error);
      next(); // Continue on error
    }
  };
};

/**
 * Feature access control based on subscription plan
 * @param {Array} requiredFeatures - Required features for access
 * @returns {Function} Middleware function
 */
const checkFeatureAccess = (requiredFeatures = []) => {
  return (req, res, next) => {
    try {
      // Super admin has access to all features
      if (req.user.role === 'super_admin') {
        return next();
      }

      const userPlan = req.user.organization?.plan || 'free';
      
      // Define feature access by plan
      const planFeatures = {
        free: ['basic_scans', 'basic_reports'],
        basic: ['basic_scans', 'basic_reports', 'threat_intel', 'email_alerts'],
        professional: [
          'basic_scans', 'basic_reports', 'threat_intel', 'email_alerts',
          'advanced_scans', 'custom_reports', 'api_access', 'slack_integration'
        ],
        enterprise: [
          'basic_scans', 'basic_reports', 'threat_intel', 'email_alerts',
          'advanced_scans', 'custom_reports', 'api_access', 'slack_integration',
          'premium_support', 'custom_integrations', 'advanced_analytics',
          'compliance_reports', 'soc_automation'
        ]
      };

      const availableFeatures = planFeatures[userPlan] || planFeatures.free;
      
      // Check if user has access to required features
      const hasAccess = requiredFeatures.every(feature => 
        availableFeatures.includes(feature)
      );

      if (!hasAccess) {
        logger.security('Feature access denied', {
          userId: req.user._id,
          userPlan,
          requiredFeatures,
          availableFeatures,
          ip: req.ip,
          url: req.originalUrl
        });
        
        return res.status(403).json({
          success: false,
          message: 'Access denied. Your subscription plan does not include this feature.',
          requiredFeatures,
          currentPlan: userPlan,
          upgradeRequired: true
        });
      }

      req.userFeatures = availableFeatures;
      next();
    } catch (error) {
      logger.error('Feature access control error:', error);
      res.status(500).json({
        success: false,
        message: 'Server error during feature access control.'
      });
    }
  };
};

/**
 * Optional authentication middleware
 * Authenticates user if token is provided, but doesn't require it
 */
const optionalAuth = async (req, res, next) => {
  try {
    const authHeader = req.header('Authorization');
    
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return next();
    }

    const token = authHeader.replace('Bearer ', '');
    
    try {
      const decoded = jwt.verify(token, process.env.JWT_SECRET);
      const user = await User.findById(decoded.id)
        .select('-password')
        .populate('organization', 'name plan status');

      if (user && user.isActive) {
        req.user = user;
        req.token = token;
      }
    } catch (error) {
      // Ignore token errors for optional auth
      logger.debug('Optional auth failed:', error.message);
    }

    next();
  } catch (error) {
    logger.error('Optional authentication error:', error);
    next();
  }
};

module.exports = {
  authenticate,
  authorize,
  checkOrganizationAccess,
  userRateLimit,
  checkFeatureAccess,
  optionalAuth
};