/**
 * Threat Model
 * Defines the threat schema for threat intelligence and indicator management
 */

const mongoose = require('mongoose');

const threatSchema = new mongoose.Schema({
  // Basic Information
  title: {
    type: String,
    required: [true, 'Threat title is required'],
    trim: true,
    maxlength: [200, 'Title cannot exceed 200 characters']
  },
  description: {
    type: String,
    required: [true, 'Threat description is required'],
    trim: true
  },
  
  // Threat Classification
  type: {
    type: String,
    enum: [
      'malware', 'phishing', 'ransomware', 'apt', 'insider-threat',
      'ddos', 'data-breach', 'vulnerability', 'social-engineering',
      'supply-chain', 'zero-day', 'botnet', 'cryptojacking'
    ],
    required: [true, 'Threat type is required']
  },
  category: {
    type: String,
    enum: ['cyber-attack', 'fraud', 'espionage', 'terrorism', 'crime'],
    required: [true, 'Threat category is required']
  },
  
  // Severity and Risk Assessment
  severity: {
    type: String,
    enum: ['critical', 'high', 'medium', 'low', 'info'],
    required: [true, 'Severity is required']
  },
  confidenceLevel: {
    type: String,
    enum: ['confirmed', 'likely', 'possible', 'unlikely', 'unknown'],
    default: 'possible'
  },
  riskScore: {
    type: Number,
    min: 0,
    max: 100,
    default: 0
  },
  
  // Threat Actor Information
  threatActor: {
    name: String,
    aliases: [String],
    type: {
      type: String,
      enum: ['nation-state', 'criminal', 'hacktivist', 'insider', 'unknown']
    },
    motivation: {
      type: String,
      enum: ['financial', 'espionage', 'ideology', 'revenge', 'unknown']
    },
    sophistication: {
      type: String,
      enum: ['novice', 'practitioner', 'expert', 'innovator']
    },
    origin: String, // Country or region
    knownSince: Date
  },
  
  // Indicators of Compromise (IoCs)
  indicators: [{
    type: {
      type: String,
      enum: ['ip', 'domain', 'url', 'hash', 'email', 'filename', 'registry', 'mutex', 'yara'],
      required: true
    },
    value: {
      type: String,
      required: true,
      trim: true
    },
    description: String,
    confidence: {
      type: String,
      enum: ['high', 'medium', 'low'],
      default: 'medium'
    },
    firstSeen: {
      type: Date,
      default: Date.now
    },
    lastSeen: Date,
    source: String,
    tags: [String],
    whitelisted: {
      type: Boolean,
      default: false
    },
    whitelistedBy: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User'
    },
    whitelistedAt: Date,
    whitelistReason: String
  }],
  
  // Attack Patterns and Techniques
  attackPatterns: [{
    name: String,
    description: String,
    capecId: String, // CAPEC (Common Attack Pattern Enumeration and Classification)
    killChainPhase: {
      type: String,
      enum: [
        'reconnaissance', 'weaponization', 'delivery', 'exploitation',
        'installation', 'command-control', 'actions-objectives'
      ]
    }
  }],
  
  // MITRE ATT&CK Framework Mapping
  mitreAttack: [{
    technique: {
      type: String,
      required: true
    }, // e.g., T1046 (Network Service Scanning)
    subtechnique: String,
    tactic: {
      type: String,
      required: true
    }, // e.g., Discovery
    description: String,
    platforms: [String], // Windows, Linux, macOS, etc.
    dataSources: [String],
    defenses: [String]
  }],
  
  // Vulnerabilities Associated
  vulnerabilities: [{
    cve: String,
    title: String,
    cvssScore: Number,
    description: String,
    exploitAvailable: {
      type: Boolean,
      default: false
    },
    patchAvailable: {
      type: Boolean,
      default: false
    },
    affectedProducts: [String]
  }],
  
  // Campaign Information
  campaign: {
    name: String,
    startDate: Date,
    endDate: Date,
    active: {
      type: Boolean,
      default: true
    },
    targets: [String], // Industries, countries, organizations
    objectives: [String]
  },
  
  // Intelligence Sources
  sources: [{
    name: {
      type: String,
      required: true
    },
    type: {
      type: String,
      enum: ['osint', 'commercial', 'government', 'internal', 'community'],
      required: true
    },
    url: String,
    reliability: {
      type: String,
      enum: ['A', 'B', 'C', 'D', 'E', 'F'], // NATO standard
      default: 'C'
    },
    credibility: {
      type: String,
      enum: ['1', '2', '3', '4', '5', '6'], // NATO standard
      default: '3'
    },
    publishedAt: Date,
    collectedAt: {
      type: Date,
      default: Date.now
    }
  }],
  
  // Geographic Information
  geography: {
    origin: [String], // Countries where threat originates
    targets: [String], // Countries/regions targeted
    coordinates: {
      type: [Number], // [longitude, latitude]
      index: '2dsphere'
    }
  },
  
  // Timeline and Status
  status: {
    type: String,
    enum: ['active', 'inactive', 'mitigated', 'false-positive', 'under-investigation'],
    default: 'active'
  },
  firstDetected: {
    type: Date,
    default: Date.now
  },
  lastActivity: Date,
  resolved: {
    type: Boolean,
    default: false
  },
  resolvedAt: Date,
  resolvedBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User'
  },
  
  // Impact Assessment
  impact: {
    scope: {
      type: String,
      enum: ['individual', 'organizational', 'sectoral', 'national', 'global']
    },
    affectedSystems: [String],
    estimatedLoss: Number, // Financial impact
    downtime: Number, // in hours
    dataCompromised: {
      type: Boolean,
      default: false
    },
    recordsAffected: Number,
    businessImpact: {
      type: String,
      enum: ['none', 'minimal', 'moderate', 'significant', 'severe']
    }
  },
  
  // Organization and User Context
  organization: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Organization',
    required: true
  },
  discoveredBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User'
  },
  assignedTo: [{
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User'
  }],
  
  // Enrichment Data
  enrichment: {
    whoisData: {
      type: mongoose.Schema.Types.Mixed
    },
    dnsData: {
      type: mongoose.Schema.Types.Mixed
    },
    geoipData: {
      type: mongoose.Schema.Types.Mixed
    },
    virusTotalData: {
      type: mongoose.Schema.Types.Mixed
    },
    shodan: {
      type: mongoose.Schema.Types.Mixed
    },
    lastEnriched: Date
  },
  
  // Response and Mitigation
  response: {
    actions: [{
      type: {
        type: String,
        enum: ['block', 'monitor', 'investigate', 'contain', 'eradicate', 'recover']
      },
      description: String,
      performedBy: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User'
      },
      performedAt: {
        type: Date,
        default: Date.now
      },
      status: {
        type: String,
        enum: ['pending', 'in-progress', 'completed', 'failed']
      },
      evidence: [String] // File paths or URLs
    }],
    playbooks: [{
      name: String,
      version: String,
      executedAt: Date,
      status: String,
      results: String
    }],
    containmentStatus: {
      type: String,
      enum: ['none', 'partial', 'full'],
      default: 'none'
    }
  },
  
  // Related Threats and Context
  related: [{
    threat: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'Threat'
    },
    relationship: {
      type: String,
      enum: ['duplicate', 'similar', 'variant', 'successor', 'related']
    },
    confidence: {
      type: String,
      enum: ['high', 'medium', 'low']
    }
  }],
  
  // Intelligence Sharing
  sharing: {
    tlp: {
      type: String,
      enum: ['RED', 'AMBER', 'GREEN', 'WHITE'],
      default: 'AMBER'
    }, // Traffic Light Protocol
    shareable: {
      type: Boolean,
      default: true
    },
    sharedWith: [String], // Organization or group names
    restrictions: String
  },
  
  // Tags and Classification
  tags: [String],
  labels: [{
    name: String,
    color: String
  }],
  
  // Comments and Notes
  comments: [{
    text: String,
    author: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User'
    },
    timestamp: {
      type: Date,
      default: Date.now
    },
    type: {
      type: String,
      enum: ['analysis', 'update', 'question', 'resolution'],
      default: 'analysis'
    }
  }],
  
  // File Attachments
  attachments: [{
    name: String,
    path: String,
    type: String,
    size: Number,
    hash: String,
    uploadedBy: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User'
    },
    uploadedAt: {
      type: Date,
      default: Date.now
    }
  }]
}, {
  timestamps: true,
  toJSON: { virtuals: true },
  toObject: { virtuals: true }
});

// Indexes for performance
threatSchema.index({ organization: 1, status: 1 });
threatSchema.index({ type: 1, severity: 1 });
threatSchema.index({ 'indicators.type': 1, 'indicators.value': 1 });
threatSchema.index({ 'mitreAttack.technique': 1 });
threatSchema.index({ 'threatActor.name': 1 });
threatSchema.index({ 'sources.name': 1 });
threatSchema.index({ tags: 1 });
threatSchema.index({ firstDetected: -1 });
threatSchema.index({ lastActivity: -1 });
threatSchema.index({ 'geography.coordinates': '2dsphere' });

// Virtual for age in days
threatSchema.virtual('ageInDays').get(function() {
  return Math.floor((Date.now() - this.firstDetected.getTime()) / (1000 * 60 * 60 * 24));
});

// Virtual for threat level (combining severity and confidence)
threatSchema.virtual('threatLevel').get(function() {
  const severityWeights = {
    critical: 5,
    high: 4,
    medium: 3,
    low: 2,
    info: 1
  };
  
  const confidenceWeights = {
    confirmed: 1.0,
    likely: 0.8,
    possible: 0.6,
    unlikely: 0.4,
    unknown: 0.2
  };
  
  const severityScore = severityWeights[this.severity] || 1;
  const confidenceMultiplier = confidenceWeights[this.confidenceLevel] || 0.2;
  
  return Math.round(severityScore * confidenceMultiplier * 20); // Scale to 0-100
});

// Pre-save middleware to calculate risk score
threatSchema.pre('save', function(next) {
  if (this.isModified('severity') || this.isModified('confidenceLevel') || this.isModified('indicators')) {
    // Calculate risk score based on various factors
    let riskScore = 0;
    
    // Base score from severity
    const severityScores = {
      critical: 40,
      high: 30,
      medium: 20,
      low: 10,
      info: 5
    };
    riskScore += severityScores[this.severity] || 0;
    
    // Confidence modifier
    const confidenceModifiers = {
      confirmed: 1.5,
      likely: 1.2,
      possible: 1.0,
      unlikely: 0.7,
      unknown: 0.5
    };
    riskScore *= confidenceModifiers[this.confidenceLevel] || 1.0;
    
    // IoC count modifier
    if (this.indicators && this.indicators.length > 0) {
      riskScore += Math.min(this.indicators.length * 2, 20);
    }
    
    // Active campaign modifier
    if (this.campaign && this.campaign.active) {
      riskScore += 10;
    }
    
    // Recent activity modifier
    if (this.lastActivity && (Date.now() - this.lastActivity.getTime()) < 7 * 24 * 60 * 60 * 1000) {
      riskScore += 15;
    }
    
    this.riskScore = Math.min(Math.round(riskScore), 100);
  }
  
  // Update last activity if indicators are modified
  if (this.isModified('indicators')) {
    this.lastActivity = new Date();
  }
  
  next();
});

// Instance method to add indicator
threatSchema.methods.addIndicator = function(indicator) {
  // Check for duplicates
  const existing = this.indicators.find(ioc => 
    ioc.type === indicator.type && ioc.value === indicator.value
  );
  
  if (!existing) {
    this.indicators.push(indicator);
    return this.save();
  }
  
  return Promise.resolve(this);
};

// Instance method to enrich threat data
threatSchema.methods.enrichData = async function(enrichmentData) {
  this.enrichment = {
    ...this.enrichment,
    ...enrichmentData,
    lastEnriched: new Date()
  };
  
  return this.save();
};

// Instance method to add response action
threatSchema.methods.addResponseAction = function(action, userId) {
  this.response.actions.push({
    ...action,
    performedBy: userId,
    performedAt: new Date()
  });
  
  return this.save();
};

// Instance method to mark as resolved
threatSchema.methods.markResolved = function(userId) {
  this.resolved = true;
  this.resolvedAt = new Date();
  this.resolvedBy = userId;
  this.status = 'mitigated';
  
  return this.save();
};

// Static method to get threat statistics
threatSchema.statics.getStatistics = function(organizationId, timeframe = 30) {
  const startDate = new Date();
  startDate.setDate(startDate.getDate() - timeframe);
  
  return this.aggregate([
    {
      $match: {
        organization: organizationId,
        firstDetected: { $gte: startDate }
      }
    },
    {
      $group: {
        _id: null,
        totalThreats: { $sum: 1 },
        criticalThreats: {
          $sum: { $cond: [{ $eq: ['$severity', 'critical'] }, 1, 0] }
        },
        highThreats: {
          $sum: { $cond: [{ $eq: ['$severity', 'high'] }, 1, 0] }
        },
        activeThreats: {
          $sum: { $cond: [{ $eq: ['$status', 'active'] }, 1, 0] }
        },
        resolvedThreats: {
          $sum: { $cond: [{ $eq: ['$resolved', true] }, 1, 0] }
        },
        avgRiskScore: { $avg: '$riskScore' },
        totalIndicators: { $sum: { $size: '$indicators' } }
      }
    }
  ]);
};

// Static method to get MITRE ATT&CK heatmap data
threatSchema.statics.getMitreHeatmap = function(organizationId, timeframe = 90) {
  const startDate = new Date();
  startDate.setDate(startDate.getDate() - timeframe);
  
  return this.aggregate([
    {
      $match: {
        organization: organizationId,
        firstDetected: { $gte: startDate },
        'mitreAttack.0': { $exists: true }
      }
    },
    { $unwind: '$mitreAttack' },
    {
      $group: {
        _id: {
          technique: '$mitreAttack.technique',
          tactic: '$mitreAttack.tactic'
        },
        count: { $sum: 1 },
        severity: { $push: '$severity' },
        avgRiskScore: { $avg: '$riskScore' }
      }
    },
    {
      $project: {
        technique: '$_id.technique',
        tactic: '$_id.tactic',
        count: 1,
        avgRiskScore: 1,
        highSeverityCount: {
          $size: {
            $filter: {
              input: '$severity',
              cond: { $in: ['$$this', ['critical', 'high']] }
            }
          }
        }
      }
    },
    { $sort: { count: -1 } }
  ]);
};

module.exports = mongoose.model('Threat', threatSchema);