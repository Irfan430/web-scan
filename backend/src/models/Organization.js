/**
 * Organization Model
 * Defines the organization schema for multi-tenant SaaS functionality
 */

const mongoose = require('mongoose');

const organizationSchema = new mongoose.Schema({
  // Basic Information
  name: {
    type: String,
    required: [true, 'Organization name is required'],
    trim: true,
    maxlength: [100, 'Organization name cannot exceed 100 characters']
  },
  slug: {
    type: String,
    required: true,
    unique: true,
    lowercase: true,
    trim: true,
    match: [/^[a-z0-9-]+$/, 'Slug can only contain lowercase letters, numbers, and hyphens']
  },
  description: {
    type: String,
    trim: true,
    maxlength: [500, 'Description cannot exceed 500 characters']
  },
  website: {
    type: String,
    trim: true,
    match: [/^https?:\/\/.+/, 'Please provide a valid website URL']
  },
  
  // Contact Information
  contactInfo: {
    email: {
      type: String,
      required: [true, 'Contact email is required'],
      lowercase: true,
      trim: true,
      match: [
        /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/,
        'Please provide a valid email address'
      ]
    },
    phone: {
      type: String,
      trim: true,
      match: [/^\+?[\d\s\-\(\)]+$/, 'Please provide a valid phone number']
    },
    address: {
      street: String,
      city: String,
      state: String,
      country: String,
      zipCode: String
    }
  },
  
  // Subscription & Billing
  plan: {
    type: String,
    enum: ['free', 'basic', 'professional', 'enterprise'],
    default: 'free',
    required: true
  },
  billingInfo: {
    customerId: String, // Stripe customer ID
    subscriptionId: String, // Stripe subscription ID
    status: {
      type: String,
      enum: ['active', 'inactive', 'cancelled', 'past_due', 'unpaid', 'trialing'],
      default: 'inactive'
    },
    trialEndsAt: Date,
    currentPeriodStart: Date,
    currentPeriodEnd: Date,
    cancelAtPeriodEnd: {
      type: Boolean,
      default: false
    },
    paymentMethod: {
      type: String,
      enum: ['card', 'bank_transfer', 'invoice'],
      default: 'card'
    }
  },
  
  // Plan Limits
  limits: {
    users: {
      type: Number,
      default: 5
    },
    scansPerMonth: {
      type: Number,
      default: 100
    },
    targetsPerScan: {
      type: Number,
      default: 10
    },
    storageGB: {
      type: Number,
      default: 1
    },
    apiRequestsPerMonth: {
      type: Number,
      default: 1000
    },
    retentionDays: {
      type: Number,
      default: 30
    }
  },
  
  // Usage Statistics
  usage: {
    currentUsers: {
      type: Number,
      default: 0
    },
    scansThisMonth: {
      type: Number,
      default: 0
    },
    storageUsedGB: {
      type: Number,
      default: 0
    },
    apiRequestsThisMonth: {
      type: Number,
      default: 0
    },
    lastReset: {
      type: Date,
      default: Date.now
    }
  },
  
  // Organization Status
  status: {
    type: String,
    enum: ['active', 'suspended', 'cancelled', 'pending'],
    default: 'pending'
  },
  isActive: {
    type: Boolean,
    default: true
  },
  
  // Security Settings
  securitySettings: {
    mfaRequired: {
      type: Boolean,
      default: false
    },
    passwordPolicy: {
      minLength: {
        type: Number,
        default: 8
      },
      requireUppercase: {
        type: Boolean,
        default: true
      },
      requireLowercase: {
        type: Boolean,
        default: true
      },
      requireNumbers: {
        type: Boolean,
        default: true
      },
      requireSymbols: {
        type: Boolean,
        default: false
      },
      maxAge: {
        type: Number,
        default: 90 // days
      }
    },
    sessionTimeout: {
      type: Number,
      default: 24 // hours
    },
    ipWhitelist: [String],
    allowedDomains: [String]
  },
  
  // Integrations
  integrations: {
    slack: {
      enabled: {
        type: Boolean,
        default: false
      },
      webhookUrl: String,
      botToken: String,
      channels: [{
        name: String,
        id: String,
        types: [String] // alert types to send to this channel
      }]
    },
    telegram: {
      enabled: {
        type: Boolean,
        default: false
      },
      botToken: String,
      chatId: String
    },
    jira: {
      enabled: {
        type: Boolean,
        default: false
      },
      host: String,
      username: String,
      apiToken: String,
      projectKey: String,
      issueType: {
        type: String,
        default: 'Bug'
      }
    },
    okta: {
      enabled: {
        type: Boolean,
        default: false
      },
      domain: String,
      apiToken: String,
      groupId: String
    },
    email: {
      smtp: {
        host: String,
        port: Number,
        secure: Boolean,
        auth: {
          user: String,
          pass: String
        }
      },
      from: String,
      templates: {
        alertEmail: String,
        reportEmail: String
      }
    }
  },
  
  // Compliance & Governance
  compliance: {
    frameworks: [{
      type: String,
      enum: ['SOC2', 'ISO27001', 'NIST', 'GDPR', 'HIPAA', 'PCI-DSS'],
      enabled: Boolean,
      settings: mongoose.Schema.Types.Mixed
    }],
    dataRetention: {
      logs: {
        type: Number,
        default: 365 // days
      },
      scans: {
        type: Number,
        default: 365 // days
      },
      reports: {
        type: Number,
        default: 1095 // 3 years
      }
    },
    dataClassification: {
      enabled: {
        type: Boolean,
        default: false
      },
      levels: [{
        name: String,
        color: String,
        description: String
      }]
    }
  },
  
  // Metadata
  owner: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  industry: {
    type: String,
    enum: [
      'technology', 'healthcare', 'finance', 'education', 'government',
      'retail', 'manufacturing', 'energy', 'telecommunications', 'other'
    ]
  },
  size: {
    type: String,
    enum: ['1-10', '11-50', '51-200', '201-500', '501-1000', '1000+'],
    default: '1-10'
  },
  
  // Activity Tracking
  lastActivity: {
    type: Date,
    default: Date.now
  },
  stats: {
    totalScans: {
      type: Number,
      default: 0
    },
    totalThreats: {
      type: Number,
      default: 0
    },
    totalReports: {
      type: Number,
      default: 0
    },
    lastScanDate: Date,
    avgThreatScore: {
      type: Number,
      default: 0
    }
  }
}, {
  timestamps: true,
  toJSON: { virtuals: true },
  toObject: { virtuals: true }
});

// Indexes for performance
organizationSchema.index({ slug: 1 });
organizationSchema.index({ plan: 1 });
organizationSchema.index({ status: 1 });
organizationSchema.index({ 'billingInfo.customerId': 1 });
organizationSchema.index({ owner: 1 });

// Virtual for plan display name
organizationSchema.virtual('planDisplayName').get(function() {
  const planNames = {
    free: 'Free',
    basic: 'Basic',
    professional: 'Professional',
    enterprise: 'Enterprise'
  };
  return planNames[this.plan] || 'Unknown';
});

// Virtual for usage percentage
organizationSchema.virtual('usagePercentage').get(function() {
  return {
    users: (this.usage.currentUsers / this.limits.users) * 100,
    scans: (this.usage.scansThisMonth / this.limits.scansPerMonth) * 100,
    storage: (this.usage.storageUsedGB / this.limits.storageGB) * 100,
    apiRequests: (this.usage.apiRequestsThisMonth / this.limits.apiRequestsPerMonth) * 100
  };
});

// Virtual for subscription status
organizationSchema.virtual('subscriptionStatus').get(function() {
  if (this.plan === 'free') return 'Free Plan';
  if (!this.billingInfo.subscriptionId) return 'No Subscription';
  
  const status = this.billingInfo.status;
  const statusMap = {
    active: 'Active',
    inactive: 'Inactive',
    cancelled: 'Cancelled',
    past_due: 'Past Due',
    unpaid: 'Unpaid',
    trialing: 'Trial'
  };
  
  return statusMap[status] || 'Unknown';
});

// Pre-save middleware to generate slug from name
organizationSchema.pre('save', function(next) {
  if (this.isModified('name') && !this.slug) {
    this.slug = this.name
      .toLowerCase()
      .replace(/[^a-z0-9\s-]/g, '')
      .replace(/\s+/g, '-')
      .replace(/-+/g, '-')
      .trim();
  }
  next();
});

// Pre-save middleware to set plan limits
organizationSchema.pre('save', function(next) {
  if (this.isModified('plan')) {
    const planLimits = {
      free: {
        users: 5,
        scansPerMonth: 100,
        targetsPerScan: 10,
        storageGB: 1,
        apiRequestsPerMonth: 1000,
        retentionDays: 30
      },
      basic: {
        users: 25,
        scansPerMonth: 500,
        targetsPerScan: 50,
        storageGB: 10,
        apiRequestsPerMonth: 10000,
        retentionDays: 90
      },
      professional: {
        users: 100,
        scansPerMonth: 2000,
        targetsPerScan: 200,
        storageGB: 50,
        apiRequestsPerMonth: 50000,
        retentionDays: 180
      },
      enterprise: {
        users: 500,
        scansPerMonth: 10000,
        targetsPerScan: 1000,
        storageGB: 500,
        apiRequestsPerMonth: 500000,
        retentionDays: 365
      }
    };
    
    this.limits = { ...this.limits, ...planLimits[this.plan] };
  }
  next();
});

// Instance method to check if limit is exceeded
organizationSchema.methods.isLimitExceeded = function(resource) {
  const usage = this.usage[resource] || 0;
  const limit = this.limits[resource] || 0;
  return usage >= limit;
};

// Instance method to increment usage
organizationSchema.methods.incrementUsage = async function(resource, amount = 1) {
  const update = {};
  update[`usage.${resource}`] = (this.usage[resource] || 0) + amount;
  
  return await this.constructor.findByIdAndUpdate(
    this._id,
    { $inc: update },
    { new: true }
  );
};

// Instance method to reset monthly usage
organizationSchema.methods.resetMonthlyUsage = async function() {
  return await this.constructor.findByIdAndUpdate(
    this._id,
    {
      $set: {
        'usage.scansThisMonth': 0,
        'usage.apiRequestsThisMonth': 0,
        'usage.lastReset': new Date()
      }
    },
    { new: true }
  );
};

// Static method to find organizations needing usage reset
organizationSchema.statics.findNeedingUsageReset = function() {
  const lastMonth = new Date();
  lastMonth.setMonth(lastMonth.getMonth() - 1);
  
  return this.find({
    'usage.lastReset': { $lt: lastMonth }
  });
};

// Static method to get plan features
organizationSchema.statics.getPlanFeatures = function(plan) {
  const features = {
    free: [
      'Basic vulnerability scans',
      'Basic threat intelligence',
      'Email alerts',
      'PDF reports',
      'Community support'
    ],
    basic: [
      'All Free features',
      'Advanced vulnerability scans',
      'Real-time threat intelligence',
      'Slack integration',
      'Custom reports',
      'Email support'
    ],
    professional: [
      'All Basic features',
      'SOC automation',
      'API access',
      'MITRE ATT&CK mapping',
      'Advanced analytics',
      'Telegram integration',
      'Priority support'
    ],
    enterprise: [
      'All Professional features',
      'Custom integrations',
      'Compliance reporting',
      'SSO integration',
      'Dedicated support',
      'SLA guarantee',
      'Custom deployment'
    ]
  };
  
  return features[plan] || features.free;
};

module.exports = mongoose.model('Organization', organizationSchema);