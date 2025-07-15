/**
 * User Model
 * Defines the user schema for authentication, roles, and multi-tenancy
 */

const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const userSchema = new mongoose.Schema({
  // Basic Information
  firstName: {
    type: String,
    required: [true, 'First name is required'],
    trim: true,
    maxlength: [50, 'First name cannot exceed 50 characters']
  },
  lastName: {
    type: String,
    required: [true, 'Last name is required'],
    trim: true,
    maxlength: [50, 'Last name cannot exceed 50 characters']
  },
  email: {
    type: String,
    required: [true, 'Email is required'],
    unique: true,
    lowercase: true,
    trim: true,
    match: [
      /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/,
      'Please provide a valid email address'
    ]
  },
  password: {
    type: String,
    required: [true, 'Password is required'],
    minlength: [8, 'Password must be at least 8 characters long'],
    select: false // Don't return password by default
  },
  
  // Role-Based Access Control
  role: {
    type: String,
    enum: ['viewer', 'analyst', 'manager', 'admin', 'super_admin'],
    default: 'viewer',
    required: true
  },
  
  // Multi-tenancy
  organization: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Organization',
    required: function() {
      return this.role !== 'super_admin';
    }
  },
  
  // Account Status
  isActive: {
    type: Boolean,
    default: true
  },
  isEmailVerified: {
    type: Boolean,
    default: false
  },
  isMfaEnabled: {
    type: Boolean,
    default: false
  },
  
  // MFA Settings
  mfaSecret: {
    type: String,
    select: false
  },
  mfaBackupCodes: [{
    code: String,
    used: {
      type: Boolean,
      default: false
    }
  }],
  
  // Profile Information
  avatar: {
    type: String,
    default: null
  },
  phone: {
    type: String,
    trim: true,
    match: [/^\+?[\d\s\-\(\)]+$/, 'Please provide a valid phone number']
  },
  timezone: {
    type: String,
    default: 'UTC'
  },
  preferences: {
    theme: {
      type: String,
      enum: ['light', 'dark', 'auto'],
      default: 'light'
    },
    language: {
      type: String,
      default: 'en'
    },
    notifications: {
      email: {
        type: Boolean,
        default: true
      },
      push: {
        type: Boolean,
        default: true
      },
      slack: {
        type: Boolean,
        default: false
      },
      telegram: {
        type: Boolean,
        default: false
      }
    },
    dashboard: {
      defaultView: {
        type: String,
        enum: ['overview', 'scans', 'threats', 'reports'],
        default: 'overview'
      },
      refreshInterval: {
        type: Number,
        default: 30000, // 30 seconds
        min: 5000,
        max: 300000
      }
    }
  },
  
  // Security Information
  lastActivity: {
    type: Date,
    default: Date.now
  },
  lastLogin: {
    type: Date
  },
  loginHistory: [{
    timestamp: {
      type: Date,
      default: Date.now
    },
    ipAddress: String,
    userAgent: String,
    location: {
      country: String,
      city: String,
      coordinates: [Number] // [longitude, latitude]
    },
    success: {
      type: Boolean,
      default: true
    }
  }],
  failedLoginAttempts: {
    type: Number,
    default: 0
  },
  lockUntil: Date,
  
  // Password Reset
  passwordResetToken: String,
  passwordResetExpires: Date,
  passwordChangedAt: Date,
  
  // Email Verification
  emailVerificationToken: String,
  emailVerificationExpires: Date,
  
  // API Access
  apiKey: {
    type: String,
    unique: true,
    sparse: true
  },
  apiKeyCreatedAt: Date,
  apiUsage: {
    requests: {
      type: Number,
      default: 0
    },
    lastRequest: Date,
    monthlyLimit: {
      type: Number,
      default: 1000
    }
  },
  
  // Permissions (for fine-grained access control)
  permissions: [{
    resource: {
      type: String,
      required: true
    },
    actions: [{
      type: String,
      enum: ['create', 'read', 'update', 'delete', 'execute']
    }]
  }],
  
  // Billing Information
  billingInfo: {
    customerId: String, // Stripe customer ID
    subscriptionId: String,
    subscriptionStatus: {
      type: String,
      enum: ['active', 'inactive', 'cancelled', 'past_due', 'unpaid'],
      default: 'inactive'
    }
  }
}, {
  timestamps: true,
  toJSON: { 
    virtuals: true,
    transform: function(doc, ret) {
      delete ret.password;
      delete ret.mfaSecret;
      delete ret.passwordResetToken;
      delete ret.emailVerificationToken;
      return ret;
    }
  },
  toObject: { virtuals: true }
});

// Indexes for performance
userSchema.index({ email: 1 });
userSchema.index({ organization: 1 });
userSchema.index({ role: 1 });
userSchema.index({ isActive: 1 });
userSchema.index({ apiKey: 1 }, { sparse: true });
userSchema.index({ 'loginHistory.timestamp': -1 });

// Virtual for full name
userSchema.virtual('fullName').get(function() {
  return `${this.firstName} ${this.lastName}`;
});

// Virtual for account lock status
userSchema.virtual('isLocked').get(function() {
  return !!(this.lockUntil && this.lockUntil > Date.now());
});

// Pre-save middleware to hash password
userSchema.pre('save', async function(next) {
  // Only hash the password if it has been modified (or is new)
  if (!this.isModified('password')) return next();
  
  try {
    // Hash the password with cost of 12
    const salt = await bcrypt.genSalt(parseInt(process.env.BCRYPT_ROUNDS) || 12);
    this.password = await bcrypt.hash(this.password, salt);
    
    // Set password changed timestamp
    this.passwordChangedAt = new Date();
    
    next();
  } catch (error) {
    next(error);
  }
});

// Pre-save middleware to generate API key
userSchema.pre('save', function(next) {
  if (this.isNew && !this.apiKey) {
    this.apiKey = this.generateApiKey();
    this.apiKeyCreatedAt = new Date();
  }
  next();
});

// Instance method to check password
userSchema.methods.comparePassword = async function(candidatePassword) {
  if (!this.password) {
    throw new Error('Password not set for this user');
  }
  return await bcrypt.compare(candidatePassword, this.password);
};

// Instance method to generate JWT token
userSchema.methods.generateAuthToken = function() {
  const payload = {
    id: this._id,
    email: this.email,
    role: this.role,
    organization: this.organization
  };
  
  return jwt.sign(payload, process.env.JWT_SECRET, {
    expiresIn: process.env.JWT_EXPIRE || '24h'
  });
};

// Instance method to generate API key
userSchema.methods.generateApiKey = function() {
  const crypto = require('crypto');
  return `cybersec_${crypto.randomBytes(32).toString('hex')}`;
};

// Instance method to check if password was changed after JWT was issued
userSchema.methods.changedPasswordAfter = function(JWTTimestamp) {
  if (this.passwordChangedAt) {
    const changedTimestamp = parseInt(this.passwordChangedAt.getTime() / 1000, 10);
    return JWTTimestamp < changedTimestamp;
  }
  return false;
};

// Instance method to create password reset token
userSchema.methods.createPasswordResetToken = function() {
  const crypto = require('crypto');
  const resetToken = crypto.randomBytes(32).toString('hex');
  
  this.passwordResetToken = crypto
    .createHash('sha256')
    .update(resetToken)
    .digest('hex');
    
  this.passwordResetExpires = Date.now() + 10 * 60 * 1000; // 10 minutes
  
  return resetToken;
};

// Instance method to create email verification token
userSchema.methods.createEmailVerificationToken = function() {
  const crypto = require('crypto');
  const verificationToken = crypto.randomBytes(32).toString('hex');
  
  this.emailVerificationToken = crypto
    .createHash('sha256')
    .update(verificationToken)
    .digest('hex');
    
  this.emailVerificationExpires = Date.now() + 24 * 60 * 60 * 1000; // 24 hours
  
  return verificationToken;
};

// Instance method to handle failed login attempts
userSchema.methods.incrementLoginAttempts = function() {
  // If we have a previous lock that has expired, restart at 1
  if (this.lockUntil && this.lockUntil < Date.now()) {
    return this.updateOne({
      $unset: { lockUntil: 1 },
      $set: { failedLoginAttempts: 1 }
    });
  }
  
  const updates = { $inc: { failedLoginAttempts: 1 } };
  
  // If we've reached max attempts and it's not locked already, lock account
  const maxAttempts = 5;
  const lockTime = 2 * 60 * 60 * 1000; // 2 hours
  
  if (this.failedLoginAttempts + 1 >= maxAttempts && !this.isLocked) {
    updates.$set = { lockUntil: Date.now() + lockTime };
  }
  
  return this.updateOne(updates);
};

// Instance method to record successful login
userSchema.methods.recordLogin = function(ipAddress, userAgent, location = {}) {
  const loginRecord = {
    timestamp: new Date(),
    ipAddress,
    userAgent,
    location,
    success: true
  };
  
  // Keep only last 50 login records
  this.loginHistory.unshift(loginRecord);
  if (this.loginHistory.length > 50) {
    this.loginHistory = this.loginHistory.slice(0, 50);
  }
  
  // Reset failed attempts and lock
  this.failedLoginAttempts = 0;
  this.lockUntil = undefined;
  this.lastLogin = new Date();
  this.lastActivity = new Date();
  
  return this.save();
};

// Static method to find by API key
userSchema.statics.findByApiKey = function(apiKey) {
  return this.findOne({ apiKey, isActive: true })
    .populate('organization', 'name plan status');
};

// Static method to get user permissions
userSchema.statics.getUserPermissions = function(role) {
  const rolePermissions = {
    viewer: [
      { resource: 'scans', actions: ['read'] },
      { resource: 'reports', actions: ['read'] },
      { resource: 'dashboard', actions: ['read'] }
    ],
    analyst: [
      { resource: 'scans', actions: ['create', 'read', 'execute'] },
      { resource: 'reports', actions: ['create', 'read'] },
      { resource: 'threats', actions: ['read', 'update'] },
      { resource: 'dashboard', actions: ['read'] }
    ],
    manager: [
      { resource: 'scans', actions: ['create', 'read', 'update', 'execute'] },
      { resource: 'reports', actions: ['create', 'read', 'update'] },
      { resource: 'threats', actions: ['create', 'read', 'update'] },
      { resource: 'users', actions: ['read', 'update'] },
      { resource: 'dashboard', actions: ['read'] }
    ],
    admin: [
      { resource: '*', actions: ['create', 'read', 'update', 'delete', 'execute'] }
    ],
    super_admin: [
      { resource: '*', actions: ['create', 'read', 'update', 'delete', 'execute'] }
    ]
  };
  
  return rolePermissions[role] || rolePermissions.viewer;
};

module.exports = mongoose.model('User', userSchema);