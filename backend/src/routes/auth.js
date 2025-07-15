/**
 * Authentication Routes
 * Handles user registration, login, password reset, MFA, and JWT token management
 */

const express = require('express');
const { body, validationResult } = require('express-validator');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const speakeasy = require('speakeasy');
const QRCode = require('qrcode');

const User = require('../models/User');
const Organization = require('../models/Organization');
const { authenticate, authorize } = require('../middleware/auth');
const { catchAsync, createError } = require('../middleware/errorHandler');
const logger = require('../config/logger');
const { cache } = require('../config/redis');

const router = express.Router();

/**
 * @swagger
 * /api/auth/register:
 *   post:
 *     summary: Register a new user and organization
 *     tags: [Authentication]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - firstName
 *               - lastName
 *               - email
 *               - password
 *               - organizationName
 *             properties:
 *               firstName:
 *                 type: string
 *               lastName:
 *                 type: string
 *               email:
 *                 type: string
 *                 format: email
 *               password:
 *                 type: string
 *                 minLength: 8
 *               organizationName:
 *                 type: string
 *               organizationIndustry:
 *                 type: string
 *               organizationSize:
 *                 type: string
 */
router.post('/register', [
  body('firstName')
    .trim()
    .isLength({ min: 2, max: 50 })
    .withMessage('First name must be between 2 and 50 characters'),
  body('lastName')
    .trim()
    .isLength({ min: 2, max: 50 })
    .withMessage('Last name must be between 2 and 50 characters'),
  body('email')
    .isEmail()
    .normalizeEmail()
    .withMessage('Please provide a valid email address'),
  body('password')
    .isLength({ min: 8 })
    .withMessage('Password must be at least 8 characters long')
    .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)/)
    .withMessage('Password must contain at least one lowercase letter, one uppercase letter, and one number'),
  body('organizationName')
    .trim()
    .isLength({ min: 2, max: 100 })
    .withMessage('Organization name must be between 2 and 100 characters'),
], catchAsync(async (req, res) => {
  // Check for validation errors
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({
      success: false,
      message: 'Validation failed',
      errors: errors.array()
    });
  }

  const {
    firstName,
    lastName,
    email,
    password,
    organizationName,
    organizationIndustry = 'technology',
    organizationSize = '1-10'
  } = req.body;

  // Check if user already exists
  const existingUser = await User.findOne({ email });
  if (existingUser) {
    return res.status(400).json({
      success: false,
      message: 'User with this email already exists'
    });
  }

  // Check if organization name is already taken
  const existingOrg = await Organization.findOne({ name: organizationName });
  if (existingOrg) {
    return res.status(400).json({
      success: false,
      message: 'Organization name is already taken'
    });
  }

  try {
    // Create organization first
    const organization = new Organization({
      name: organizationName,
      contactInfo: {
        email: email
      },
      industry: organizationIndustry,
      size: organizationSize,
      status: 'active'
    });

    await organization.save();

    // Create user
    const user = new User({
      firstName,
      lastName,
      email,
      password,
      role: 'admin', // First user in organization is admin
      organization: organization._id
    });

    await user.save();

    // Update organization owner
    organization.owner = user._id;
    await organization.save();

    // Generate email verification token
    const verificationToken = user.createEmailVerificationToken();
    await user.save();

    // Generate JWT token
    const token = user.generateAuthToken();

    logger.auth('register', user._id, true, {
      organizationId: organization._id,
      ip: req.ip
    });

    res.status(201).json({
      success: true,
      message: 'User and organization created successfully',
      data: {
        user: {
          id: user._id,
          firstName: user.firstName,
          lastName: user.lastName,
          email: user.email,
          role: user.role,
          isEmailVerified: user.isEmailVerified
        },
        organization: {
          id: organization._id,
          name: organization.name,
          plan: organization.plan
        },
        token,
        verificationTokenSent: true
      }
    });

    // TODO: Send verification email in background
    // await queueService.addEmailJob('verification', {
    //   to: email,
    //   token: verificationToken,
    //   user: user
    // });

  } catch (error) {
    logger.error('Registration error:', error);
    
    // Cleanup if organization was created but user creation failed
    if (organization._id) {
      await Organization.findByIdAndDelete(organization._id);
    }

    throw createError('Registration failed', 500);
  }
}));

/**
 * @swagger
 * /api/auth/login:
 *   post:
 *     summary: Login user
 *     tags: [Authentication]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - email
 *               - password
 *             properties:
 *               email:
 *                 type: string
 *                 format: email
 *               password:
 *                 type: string
 *               mfaToken:
 *                 type: string
 */
router.post('/login', [
  body('email')
    .isEmail()
    .normalizeEmail()
    .withMessage('Please provide a valid email address'),
  body('password')
    .notEmpty()
    .withMessage('Password is required'),
], catchAsync(async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({
      success: false,
      message: 'Validation failed',
      errors: errors.array()
    });
  }

  const { email, password, mfaToken } = req.body;

  // Find user and include password
  const user = await User.findOne({ email })
    .select('+password')
    .populate('organization', 'name plan status');

  if (!user) {
    logger.auth('login', email, false, {
      reason: 'user_not_found',
      ip: req.ip
    });
    
    return res.status(401).json({
      success: false,
      message: 'Invalid email or password'
    });
  }

  // Check if account is locked
  if (user.isLocked) {
    logger.auth('login', user._id, false, {
      reason: 'account_locked',
      ip: req.ip
    });
    
    return res.status(423).json({
      success: false,
      message: 'Account is temporarily locked due to too many failed attempts'
    });
  }

  // Check if user is active
  if (!user.isActive) {
    logger.auth('login', user._id, false, {
      reason: 'account_inactive',
      ip: req.ip
    });
    
    return res.status(401).json({
      success: false,
      message: 'Account is deactivated'
    });
  }

  // Check organization status
  if (user.organization && user.organization.status !== 'active') {
    logger.auth('login', user._id, false, {
      reason: 'organization_inactive',
      ip: req.ip
    });
    
    return res.status(403).json({
      success: false,
      message: 'Organization account is suspended'
    });
  }

  // Verify password
  const isPasswordValid = await user.comparePassword(password);
  if (!isPasswordValid) {
    await user.incrementLoginAttempts();
    
    logger.auth('login', user._id, false, {
      reason: 'invalid_password',
      ip: req.ip
    });
    
    return res.status(401).json({
      success: false,
      message: 'Invalid email or password'
    });
  }

  // Check MFA if enabled
  if (user.isMfaEnabled) {
    if (!mfaToken) {
      return res.status(200).json({
        success: false,
        message: 'MFA token required',
        requiresMfa: true,
        userId: user._id
      });
    }

    const isValidMfaToken = speakeasy.totp.verify({
      secret: user.mfaSecret,
      encoding: 'base32',
      token: mfaToken,
      window: 2
    });

    if (!isValidMfaToken) {
      logger.auth('login', user._id, false, {
        reason: 'invalid_mfa',
        ip: req.ip
      });
      
      return res.status(401).json({
        success: false,
        message: 'Invalid MFA token'
      });
    }
  }

  // Generate JWT token
  const token = user.generateAuthToken();

  // Record successful login
  await user.recordLogin(req.ip, req.get('User-Agent'), {
    // TODO: Add geolocation data
  });

  logger.auth('login', user._id, true, {
    organizationId: user.organization?._id,
    ip: req.ip
  });

  res.json({
    success: true,
    message: 'Login successful',
    data: {
      user: {
        id: user._id,
        firstName: user.firstName,
        lastName: user.lastName,
        email: user.email,
        role: user.role,
        isEmailVerified: user.isEmailVerified,
        isMfaEnabled: user.isMfaEnabled,
        preferences: user.preferences
      },
      organization: user.organization ? {
        id: user.organization._id,
        name: user.organization.name,
        plan: user.organization.plan
      } : null,
      token,
      expiresIn: process.env.JWT_EXPIRE || '24h'
    }
  });
}));

/**
 * @swagger
 * /api/auth/logout:
 *   post:
 *     summary: Logout user (blacklist token)
 *     tags: [Authentication]
 *     security:
 *       - bearerAuth: []
 */
router.post('/logout', authenticate, catchAsync(async (req, res) => {
  const token = req.token;
  
  // Add token to blacklist
  const decoded = jwt.decode(token);
  const expiresIn = decoded.exp - Math.floor(Date.now() / 1000);
  
  if (expiresIn > 0) {
    await cache.set(`blacklist:${token}`, true, expiresIn);
  }

  logger.auth('logout', req.user._id, true, {
    ip: req.ip
  });

  res.json({
    success: true,
    message: 'Logout successful'
  });
}));

/**
 * @swagger
 * /api/auth/refresh:
 *   post:
 *     summary: Refresh JWT token
 *     tags: [Authentication]
 *     security:
 *       - bearerAuth: []
 */
router.post('/refresh', authenticate, catchAsync(async (req, res) => {
  const user = req.user;
  
  // Generate new token
  const newToken = user.generateAuthToken();
  
  // Optionally blacklist old token
  const oldToken = req.token;
  const decoded = jwt.decode(oldToken);
  const expiresIn = decoded.exp - Math.floor(Date.now() / 1000);
  
  if (expiresIn > 0) {
    await cache.set(`blacklist:${oldToken}`, true, expiresIn);
  }

  res.json({
    success: true,
    message: 'Token refreshed successfully',
    data: {
      token: newToken,
      expiresIn: process.env.JWT_EXPIRE || '24h'
    }
  });
}));

/**
 * @swagger
 * /api/auth/forgot-password:
 *   post:
 *     summary: Request password reset
 *     tags: [Authentication]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - email
 *             properties:
 *               email:
 *                 type: string
 *                 format: email
 */
router.post('/forgot-password', [
  body('email')
    .isEmail()
    .normalizeEmail()
    .withMessage('Please provide a valid email address'),
], catchAsync(async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({
      success: false,
      message: 'Validation failed',
      errors: errors.array()
    });
  }

  const { email } = req.body;

  const user = await User.findOne({ email, isActive: true });
  
  // Always return success to prevent email enumeration
  if (!user) {
    return res.json({
      success: true,
      message: 'If the email exists, a password reset link has been sent'
    });
  }

  // Generate reset token
  const resetToken = user.createPasswordResetToken();
  await user.save();

  logger.security('Password reset requested', {
    userId: user._id,
    email: user.email,
    ip: req.ip
  });

  res.json({
    success: true,
    message: 'If the email exists, a password reset link has been sent'
  });

  // TODO: Send reset email in background
  // await queueService.addEmailJob('password-reset', {
  //   to: email,
  //   token: resetToken,
  //   user: user
  // });
}));

/**
 * @swagger
 * /api/auth/reset-password:
 *   post:
 *     summary: Reset password with token
 *     tags: [Authentication]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - token
 *               - password
 *             properties:
 *               token:
 *                 type: string
 *               password:
 *                 type: string
 *                 minLength: 8
 */
router.post('/reset-password', [
  body('token')
    .notEmpty()
    .withMessage('Reset token is required'),
  body('password')
    .isLength({ min: 8 })
    .withMessage('Password must be at least 8 characters long')
    .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)/)
    .withMessage('Password must contain at least one lowercase letter, one uppercase letter, and one number'),
], catchAsync(async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({
      success: false,
      message: 'Validation failed',
      errors: errors.array()
    });
  }

  const { token, password } = req.body;

  // Hash the token to match what's stored in database
  const hashedToken = crypto
    .createHash('sha256')
    .update(token)
    .digest('hex');

  const user = await User.findOne({
    passwordResetToken: hashedToken,
    passwordResetExpires: { $gt: Date.now() }
  });

  if (!user) {
    return res.status(400).json({
      success: false,
      message: 'Invalid or expired reset token'
    });
  }

  // Update password
  user.password = password;
  user.passwordResetToken = undefined;
  user.passwordResetExpires = undefined;
  
  await user.save();

  logger.security('Password reset completed', {
    userId: user._id,
    email: user.email,
    ip: req.ip
  });

  res.json({
    success: true,
    message: 'Password reset successful'
  });
}));

/**
 * @swagger
 * /api/auth/setup-mfa:
 *   post:
 *     summary: Setup MFA for user
 *     tags: [Authentication]
 *     security:
 *       - bearerAuth: []
 */
router.post('/setup-mfa', authenticate, catchAsync(async (req, res) => {
  const user = req.user;

  if (user.isMfaEnabled) {
    return res.status(400).json({
      success: false,
      message: 'MFA is already enabled'
    });
  }

  // Generate secret
  const secret = speakeasy.generateSecret({
    name: `${user.email} (Cybersec Platform)`,
    issuer: 'Cybersecurity Platform'
  });

  // Generate QR code
  const qrCodeUrl = await QRCode.toDataURL(secret.otpauth_url);

  // Store secret temporarily (not saved until verified)
  await cache.set(`mfa_setup:${user._id}`, secret.base32, 300); // 5 minutes

  res.json({
    success: true,
    message: 'MFA setup initiated',
    data: {
      qrCode: qrCodeUrl,
      secret: secret.base32,
      backupCodes: [] // TODO: Generate backup codes
    }
  });
}));

/**
 * @swagger
 * /api/auth/verify-mfa:
 *   post:
 *     summary: Verify and enable MFA
 *     tags: [Authentication]
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - token
 *             properties:
 *               token:
 *                 type: string
 */
router.post('/verify-mfa', authenticate, [
  body('token')
    .isLength({ min: 6, max: 6 })
    .isNumeric()
    .withMessage('MFA token must be 6 digits'),
], catchAsync(async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({
      success: false,
      message: 'Validation failed',
      errors: errors.array()
    });
  }

  const { token } = req.body;
  const user = req.user;

  // Get temporary secret
  const secret = await cache.get(`mfa_setup:${user._id}`);
  if (!secret) {
    return res.status(400).json({
      success: false,
      message: 'MFA setup session expired. Please restart setup.'
    });
  }

  // Verify token
  const isValid = speakeasy.totp.verify({
    secret: secret,
    encoding: 'base32',
    token: token,
    window: 2
  });

  if (!isValid) {
    return res.status(400).json({
      success: false,
      message: 'Invalid MFA token'
    });
  }

  // Save secret and enable MFA
  user.mfaSecret = secret;
  user.isMfaEnabled = true;
  await user.save();

  // Clear temporary secret
  await cache.del(`mfa_setup:${user._id}`);

  logger.security('MFA enabled', {
    userId: user._id,
    email: user.email,
    ip: req.ip
  });

  res.json({
    success: true,
    message: 'MFA enabled successfully'
  });
}));

/**
 * @swagger
 * /api/auth/disable-mfa:
 *   post:
 *     summary: Disable MFA for user
 *     tags: [Authentication]
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - password
 *             properties:
 *               password:
 *                 type: string
 */
router.post('/disable-mfa', authenticate, [
  body('password')
    .notEmpty()
    .withMessage('Password is required to disable MFA'),
], catchAsync(async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({
      success: false,
      message: 'Validation failed',
      errors: errors.array()
    });
  }

  const { password } = req.body;
  const user = await User.findById(req.user._id).select('+password');

  // Verify password
  const isPasswordValid = await user.comparePassword(password);
  if (!isPasswordValid) {
    return res.status(401).json({
      success: false,
      message: 'Invalid password'
    });
  }

  // Disable MFA
  user.isMfaEnabled = false;
  user.mfaSecret = undefined;
  user.mfaBackupCodes = [];
  await user.save();

  logger.security('MFA disabled', {
    userId: user._id,
    email: user.email,
    ip: req.ip
  });

  res.json({
    success: true,
    message: 'MFA disabled successfully'
  });
}));

/**
 * @swagger
 * /api/auth/me:
 *   get:
 *     summary: Get current user profile
 *     tags: [Authentication]
 *     security:
 *       - bearerAuth: []
 */
router.get('/me', authenticate, catchAsync(async (req, res) => {
  const user = await User.findById(req.user._id)
    .populate('organization', 'name plan status')
    .select('-password -mfaSecret');

  res.json({
    success: true,
    data: {
      user: user
    }
  });
}));

module.exports = router;