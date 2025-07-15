/**
 * Scan Model
 * Defines the scan schema for vulnerability scanning and assessment
 */

const mongoose = require('mongoose');

const scanSchema = new mongoose.Schema({
  // Basic Information
  name: {
    type: String,
    required: [true, 'Scan name is required'],
    trim: true,
    maxlength: [100, 'Scan name cannot exceed 100 characters']
  },
  description: {
    type: String,
    trim: true,
    maxlength: [500, 'Description cannot exceed 500 characters']
  },
  
  // Scan Configuration
  type: {
    type: String,
    enum: ['nmap', 'nikto', 'custom', 'brute-force', 'web-app', 'network', 'compliance'],
    required: [true, 'Scan type is required']
  },
  targets: [{
    type: {
      type: String,
      enum: ['ip', 'domain', 'url', 'range'],
      required: true
    },
    value: {
      type: String,
      required: true,
      trim: true
    },
    ports: [String], // Port ranges or specific ports
    protocols: [{
      type: String,
      enum: ['tcp', 'udp', 'icmp'],
      default: 'tcp'
    }]
  }],
  
  // Scan Parameters
  parameters: {
    scanType: {
      type: String,
      enum: ['quick', 'standard', 'comprehensive', 'stealth', 'aggressive'],
      default: 'standard'
    },
    timeout: {
      type: Number,
      default: 300, // seconds
      min: 30,
      max: 3600
    },
    maxThreads: {
      type: Number,
      default: 10,
      min: 1,
      max: 100
    },
    excludePorts: [String],
    customFlags: [String],
    scripts: [String], // NSE scripts for Nmap
    payloads: [String], // Custom payloads
    wordlists: [String], // Wordlists for brute force
    userAgents: [String], // Custom user agents
    headers: [{
      name: String,
      value: String
    }]
  },
  
  // Organization and User
  organization: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Organization',
    required: true
  },
  createdBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  assignedTo: [{
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User'
  }],
  
  // Scan Status and Execution
  status: {
    type: String,
    enum: ['pending', 'queued', 'running', 'paused', 'completed', 'failed', 'cancelled'],
    default: 'pending'
  },
  priority: {
    type: String,
    enum: ['low', 'medium', 'high', 'critical'],
    default: 'medium'
  },
  scheduledAt: Date,
  startedAt: Date,
  completedAt: Date,
  duration: Number, // in seconds
  
  // Progress Tracking
  progress: {
    percentage: {
      type: Number,
      default: 0,
      min: 0,
      max: 100
    },
    currentTarget: String,
    targetIndex: {
      type: Number,
      default: 0
    },
    totalTargets: {
      type: Number,
      default: 0
    },
    estimatedTimeRemaining: Number, // in seconds
    lastUpdate: {
      type: Date,
      default: Date.now
    }
  },
  
  // Results Summary
  summary: {
    totalVulnerabilities: {
      type: Number,
      default: 0
    },
    criticalCount: {
      type: Number,
      default: 0
    },
    highCount: {
      type: Number,
      default: 0
    },
    mediumCount: {
      type: Number,
      default: 0
    },
    lowCount: {
      type: Number,
      default: 0
    },
    infoCount: {
      type: Number,
      default: 0
    },
    hostsScanned: {
      type: Number,
      default: 0
    },
    servicesFound: {
      type: Number,
      default: 0
    },
    openPorts: {
      type: Number,
      default: 0
    }
  },
  
  // Raw Results
  rawOutput: {
    type: String,
    default: ''
  },
  xmlOutput: String,
  jsonOutput: String,
  
  // Processed Results
  vulnerabilities: [{
    id: String,
    cve: String,
    title: String,
    description: String,
    severity: {
      type: String,
      enum: ['critical', 'high', 'medium', 'low', 'info'],
      required: true
    },
    cvssScore: {
      type: Number,
      min: 0,
      max: 10
    },
    cvssVector: String,
    category: String,
    plugin: String,
    target: String,
    port: String,
    protocol: String,
    service: String,
    evidence: String,
    solution: String,
    references: [String],
    exploitable: {
      type: Boolean,
      default: false
    },
    exploitAvailable: {
      type: Boolean,
      default: false
    },
    patchAvailable: {
      type: Boolean,
      default: false
    },
    firstDetected: {
      type: Date,
      default: Date.now
    },
    lastSeen: Date,
    falsePositive: {
      type: Boolean,
      default: false
    },
    suppressedBy: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User'
    },
    suppressedAt: Date,
    suppressionReason: String
  }],
  
  // Host Information
  hosts: [{
    ip: String,
    hostname: String,
    status: {
      type: String,
      enum: ['up', 'down', 'unknown'],
      default: 'unknown'
    },
    os: {
      name: String,
      version: String,
      confidence: Number
    },
    ports: [{
      number: Number,
      protocol: String,
      state: {
        type: String,
        enum: ['open', 'closed', 'filtered'],
        default: 'closed'
      },
      service: {
        name: String,
        version: String,
        product: String
      },
      scripts: [{
        name: String,
        output: String
      }]
    }],
    vulnerabilities: [String], // Array of vulnerability IDs
    riskScore: {
      type: Number,
      default: 0
    }
  }],
  
  // Compliance and Framework Mapping
  compliance: [{
    framework: {
      type: String,
      enum: ['NIST', 'ISO27001', 'SOC2', 'PCI-DSS', 'HIPAA', 'GDPR']
    },
    control: String,
    status: {
      type: String,
      enum: ['compliant', 'non-compliant', 'partial', 'not-applicable']
    },
    evidence: String,
    recommendation: String
  }],
  
  // MITRE ATT&CK Mapping
  mitreMapping: [{
    technique: String, // MITRE technique ID (e.g., T1046)
    tactic: String, // MITRE tactic
    subtechnique: String,
    description: String,
    severity: String
  }],
  
  // Scan Configuration and Metadata
  config: {
    maxRetries: {
      type: Number,
      default: 3
    },
    delayBetweenRequests: {
      type: Number,
      default: 100 // milliseconds
    },
    followRedirects: {
      type: Boolean,
      default: true
    },
    validateSSL: {
      type: Boolean,
      default: false
    },
    randomizeUserAgent: {
      type: Boolean,
      default: true
    },
    useProxy: {
      type: Boolean,
      default: false
    },
    proxySettings: {
      host: String,
      port: Number,
      username: String,
      password: String
    }
  },
  
  // Notifications and Reporting
  notifications: {
    enabled: {
      type: Boolean,
      default: true
    },
    channels: [{
      type: String,
      enum: ['email', 'slack', 'telegram', 'webhook']
    }],
    triggers: [{
      type: String,
      enum: ['start', 'complete', 'error', 'high-severity-found']
    }]
  },
  
  // Error Handling
  errors: [{
    timestamp: {
      type: Date,
      default: Date.now
    },
    type: String,
    message: String,
    target: String,
    stack: String
  }],
  
  // File Attachments
  files: [{
    name: String,
    path: String,
    type: String,
    size: Number,
    uploadedAt: {
      type: Date,
      default: Date.now
    }
  }],
  
  // Tags and Categories
  tags: [String],
  category: String,
  
  // Recurrence for Scheduled Scans
  recurring: {
    enabled: {
      type: Boolean,
      default: false
    },
    frequency: {
      type: String,
      enum: ['daily', 'weekly', 'monthly', 'quarterly']
    },
    interval: Number,
    nextRun: Date,
    lastRun: Date
  }
}, {
  timestamps: true,
  toJSON: { virtuals: true },
  toObject: { virtuals: true }
});

// Indexes for performance
scanSchema.index({ organization: 1, status: 1 });
scanSchema.index({ createdBy: 1 });
scanSchema.index({ type: 1 });
scanSchema.index({ 'targets.value': 1 });
scanSchema.index({ scheduledAt: 1 });
scanSchema.index({ 'vulnerabilities.severity': 1 });
scanSchema.index({ 'vulnerabilities.cve': 1 });
scanSchema.index({ createdAt: -1 });

// Virtual for risk score calculation
scanSchema.virtual('riskScore').get(function() {
  const weights = {
    critical: 10,
    high: 7,
    medium: 4,
    low: 2,
    info: 1
  };
  
  const totalScore = 
    (this.summary.criticalCount * weights.critical) +
    (this.summary.highCount * weights.high) +
    (this.summary.mediumCount * weights.medium) +
    (this.summary.lowCount * weights.low) +
    (this.summary.infoCount * weights.info);
  
  return Math.min(Math.round(totalScore / 10), 100);
});

// Virtual for scan duration in human readable format
scanSchema.virtual('durationFormatted').get(function() {
  if (!this.duration) return 'N/A';
  
  const hours = Math.floor(this.duration / 3600);
  const minutes = Math.floor((this.duration % 3600) / 60);
  const seconds = this.duration % 60;
  
  if (hours > 0) {
    return `${hours}h ${minutes}m ${seconds}s`;
  } else if (minutes > 0) {
    return `${minutes}m ${seconds}s`;
  } else {
    return `${seconds}s`;
  }
});

// Virtual for compliance percentage
scanSchema.virtual('compliancePercentage').get(function() {
  if (!this.compliance || this.compliance.length === 0) return 0;
  
  const compliantCount = this.compliance.filter(item => item.status === 'compliant').length;
  return Math.round((compliantCount / this.compliance.length) * 100);
});

// Pre-save middleware to update summary
scanSchema.pre('save', function(next) {
  if (this.isModified('vulnerabilities')) {
    this.summary.totalVulnerabilities = this.vulnerabilities.length;
    this.summary.criticalCount = this.vulnerabilities.filter(v => v.severity === 'critical').length;
    this.summary.highCount = this.vulnerabilities.filter(v => v.severity === 'high').length;
    this.summary.mediumCount = this.vulnerabilities.filter(v => v.severity === 'medium').length;
    this.summary.lowCount = this.vulnerabilities.filter(v => v.severity === 'low').length;
    this.summary.infoCount = this.vulnerabilities.filter(v => v.severity === 'info').length;
  }
  
  if (this.isModified('hosts')) {
    this.summary.hostsScanned = this.hosts.length;
    this.summary.servicesFound = this.hosts.reduce((total, host) => {
      return total + host.ports.filter(port => port.state === 'open').length;
    }, 0);
    this.summary.openPorts = this.hosts.reduce((total, host) => {
      return total + host.ports.filter(port => port.state === 'open').length;
    }, 0);
  }
  
  if (this.isModified('targets')) {
    this.progress.totalTargets = this.targets.length;
  }
  
  next();
});

// Instance method to update progress
scanSchema.methods.updateProgress = function(percentage, currentTarget = null) {
  this.progress.percentage = Math.min(Math.max(percentage, 0), 100);
  this.progress.lastUpdate = new Date();
  
  if (currentTarget) {
    this.progress.currentTarget = currentTarget;
  }
  
  // Calculate estimated time remaining
  if (percentage > 0 && this.startedAt) {
    const elapsed = (Date.now() - this.startedAt.getTime()) / 1000;
    const estimatedTotal = (elapsed / percentage) * 100;
    this.progress.estimatedTimeRemaining = Math.max(0, estimatedTotal - elapsed);
  }
  
  return this.save();
};

// Instance method to add vulnerability
scanSchema.methods.addVulnerability = function(vulnerability) {
  // Check for duplicates
  const existing = this.vulnerabilities.find(v => 
    v.cve === vulnerability.cve && 
    v.target === vulnerability.target && 
    v.port === vulnerability.port
  );
  
  if (!existing) {
    this.vulnerabilities.push(vulnerability);
    return this.save();
  }
  
  return Promise.resolve(this);
};

// Instance method to mark as complete
scanSchema.methods.markComplete = function() {
  this.status = 'completed';
  this.completedAt = new Date();
  this.progress.percentage = 100;
  
  if (this.startedAt) {
    this.duration = Math.round((this.completedAt.getTime() - this.startedAt.getTime()) / 1000);
  }
  
  return this.save();
};

// Instance method to mark as failed
scanSchema.methods.markFailed = function(error) {
  this.status = 'failed';
  this.completedAt = new Date();
  
  if (error) {
    this.errors.push({
      type: 'scan_failure',
      message: error.message || error,
      stack: error.stack
    });
  }
  
  return this.save();
};

// Static method to get scan statistics
scanSchema.statics.getStatistics = function(organizationId, timeframe = 30) {
  const startDate = new Date();
  startDate.setDate(startDate.getDate() - timeframe);
  
  return this.aggregate([
    {
      $match: {
        organization: organizationId,
        createdAt: { $gte: startDate }
      }
    },
    {
      $group: {
        _id: null,
        totalScans: { $sum: 1 },
        completedScans: {
          $sum: { $cond: [{ $eq: ['$status', 'completed'] }, 1, 0] }
        },
        failedScans: {
          $sum: { $cond: [{ $eq: ['$status', 'failed'] }, 1, 0] }
        },
        totalVulnerabilities: { $sum: '$summary.totalVulnerabilities' },
        avgRiskScore: { $avg: '$riskScore' },
        totalDuration: { $sum: '$duration' }
      }
    }
  ]);
};

module.exports = mongoose.model('Scan', scanSchema);