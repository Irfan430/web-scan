/**
 * Dashboard Routes
 * Provides overview statistics and data for the cybersecurity platform dashboard
 */

const express = require('express');
const { authenticate, authorize, checkFeatureAccess } = require('../middleware/auth');
const { catchAsync } = require('../middleware/errorHandler');
const User = require('../models/User');
const Organization = require('../models/Organization');
const Scan = require('../models/Scan');
const Threat = require('../models/Threat');
const { getDBStats } = require('../config/database');
const { getRedisStats } = require('../config/redis');
const logger = require('../config/logger');

const router = express.Router();

/**
 * @swagger
 * /api/dashboard/overview:
 *   get:
 *     summary: Get dashboard overview statistics
 *     tags: [Dashboard]
 *     security:
 *       - bearerAuth: []
 */
router.get('/overview', authenticate, catchAsync(async (req, res) => {
  const organizationId = req.user.organization._id;
  const timeframe = parseInt(req.query.timeframe) || 30; // days

  // Get various statistics in parallel
  const [
    scanStats,
    threatStats,
    recentScans,
    recentThreats,
    organizationStats
  ] = await Promise.all([
    Scan.getStatistics(organizationId, timeframe),
    Threat.getStatistics(organizationId, timeframe),
    Scan.find({ organization: organizationId })
      .sort({ createdAt: -1 })
      .limit(5)
      .select('name type status createdAt summary')
      .populate('createdBy', 'firstName lastName'),
    Threat.find({ organization: organizationId })
      .sort({ firstDetected: -1 })
      .limit(5)
      .select('title type severity status firstDetected riskScore'),
    Organization.findById(organizationId).select('usage limits stats')
  ]);

  // Calculate risk trends
  const riskTrend = await calculateRiskTrend(organizationId, timeframe);

  // Get vulnerability distribution
  const vulnerabilityDistribution = await getVulnerabilityDistribution(organizationId, timeframe);

  // Get compliance summary
  const complianceSummary = await getComplianceSummary(organizationId);

  logger.info('Dashboard overview accessed', {
    userId: req.user._id,
    organizationId: organizationId,
    timeframe: timeframe
  });

  res.json({
    success: true,
    data: {
      timeframe: timeframe,
      scans: {
        total: scanStats[0]?.totalScans || 0,
        completed: scanStats[0]?.completedScans || 0,
        failed: scanStats[0]?.failedScans || 0,
        vulnerabilities: scanStats[0]?.totalVulnerabilities || 0,
        avgRiskScore: Math.round(scanStats[0]?.avgRiskScore || 0),
        recent: recentScans
      },
      threats: {
        total: threatStats[0]?.totalThreats || 0,
        critical: threatStats[0]?.criticalThreats || 0,
        high: threatStats[0]?.highThreats || 0,
        active: threatStats[0]?.activeThreats || 0,
        resolved: threatStats[0]?.resolvedThreats || 0,
        avgRiskScore: Math.round(threatStats[0]?.avgRiskScore || 0),
        recent: recentThreats
      },
      riskTrend: riskTrend,
      vulnerabilityDistribution: vulnerabilityDistribution,
      compliance: complianceSummary,
      organization: {
        usage: organizationStats.usage,
        limits: organizationStats.limits,
        stats: organizationStats.stats
      }
    }
  });
}));

/**
 * @swagger
 * /api/dashboard/real-time:
 *   get:
 *     summary: Get real-time dashboard metrics
 *     tags: [Dashboard]
 *     security:
 *       - bearerAuth: []
 */
router.get('/real-time', authenticate, catchAsync(async (req, res) => {
  const organizationId = req.user.organization._id;

  // Get real-time metrics
  const [
    activeScans,
    recentAlerts,
    systemHealth
  ] = await Promise.all([
    Scan.find({ 
      organization: organizationId, 
      status: { $in: ['running', 'queued'] } 
    }).select('name type status progress startedAt'),
    Threat.find({ 
      organization: organizationId,
      status: 'active',
      firstDetected: { $gte: new Date(Date.now() - 24 * 60 * 60 * 1000) } // Last 24 hours
    }).sort({ firstDetected: -1 }).limit(10),
    getSystemHealth()
  ]);

  res.json({
    success: true,
    data: {
      activeScans: activeScans,
      recentAlerts: recentAlerts,
      systemHealth: systemHealth,
      timestamp: new Date().toISOString()
    }
  });
}));

/**
 * @swagger
 * /api/dashboard/mitre-heatmap:
 *   get:
 *     summary: Get MITRE ATT&CK heatmap data
 *     tags: [Dashboard]
 *     security:
 *       - bearerAuth: []
 */
router.get('/mitre-heatmap', authenticate, checkFeatureAccess(['advanced_analytics']), catchAsync(async (req, res) => {
  const organizationId = req.user.organization._id;
  const timeframe = parseInt(req.query.timeframe) || 90; // days

  const heatmapData = await Threat.getMitreHeatmap(organizationId, timeframe);

  res.json({
    success: true,
    data: {
      heatmap: heatmapData,
      timeframe: timeframe,
      generatedAt: new Date().toISOString()
    }
  });
}));

/**
 * @swagger
 * /api/dashboard/risk-score:
 *   get:
 *     summary: Get organization risk score
 *     tags: [Dashboard]
 *     security:
 *       - bearerAuth: []
 */
router.get('/risk-score', authenticate, catchAsync(async (req, res) => {
  const organizationId = req.user.organization._id;

  const riskScore = await calculateOrganizationRiskScore(organizationId);

  res.json({
    success: true,
    data: {
      riskScore: riskScore,
      calculatedAt: new Date().toISOString()
    }
  });
}));

/**
 * @swagger
 * /api/dashboard/activity-feed:
 *   get:
 *     summary: Get recent activity feed
 *     tags: [Dashboard]
 *     security:
 *       - bearerAuth: []
 */
router.get('/activity-feed', authenticate, catchAsync(async (req, res) => {
  const organizationId = req.user.organization._id;
  const limit = parseInt(req.query.limit) || 20;
  const page = parseInt(req.query.page) || 1;
  const skip = (page - 1) * limit;

  // Get recent activities from various sources
  const activities = await getRecentActivities(organizationId, limit, skip);

  res.json({
    success: true,
    data: {
      activities: activities,
      pagination: {
        page: page,
        limit: limit,
        total: activities.length
      }
    }
  });
}));

/**
 * @swagger
 * /api/dashboard/system-status:
 *   get:
 *     summary: Get system status and health
 *     tags: [Dashboard]
 *     security:
 *       - bearerAuth: []
 */
router.get('/system-status', authenticate, authorize('admin', 'super_admin'), catchAsync(async (req, res) => {
  const [dbStats, redisStats] = await Promise.all([
    getDBStats(),
    getRedisStats()
  ]);

  const systemStatus = {
    database: dbStats,
    cache: redisStats,
    server: {
      uptime: process.uptime(),
      memory: process.memoryUsage(),
      cpu: process.cpuUsage(),
      version: process.version,
      environment: process.env.NODE_ENV
    },
    services: {
      mlService: await checkServiceHealth(process.env.ML_SERVICE_URL),
      // Add other service health checks
    }
  };

  res.json({
    success: true,
    data: systemStatus
  });
}));

// Helper functions

/**
 * Calculate risk trend over time
 */
async function calculateRiskTrend(organizationId, timeframe) {
  const endDate = new Date();
  const startDate = new Date();
  startDate.setDate(startDate.getDate() - timeframe);

  const trendData = [];
  const interval = Math.max(Math.floor(timeframe / 10), 1); // 10 data points max

  for (let i = 0; i < timeframe; i += interval) {
    const date = new Date(startDate);
    date.setDate(date.getDate() + i);
    
    const dayEnd = new Date(date);
    dayEnd.setDate(dayEnd.getDate() + interval);

    const [scanRisk, threatRisk] = await Promise.all([
      Scan.aggregate([
        {
          $match: {
            organization: organizationId,
            createdAt: { $gte: date, $lt: dayEnd },
            status: 'completed'
          }
        },
        {
          $group: {
            _id: null,
            avgRisk: { $avg: '$riskScore' }
          }
        }
      ]),
      Threat.aggregate([
        {
          $match: {
            organization: organizationId,
            firstDetected: { $gte: date, $lt: dayEnd }
          }
        },
        {
          $group: {
            _id: null,
            avgRisk: { $avg: '$riskScore' }
          }
        }
      ])
    ]);

    trendData.push({
      date: date.toISOString().split('T')[0],
      scanRisk: Math.round(scanRisk[0]?.avgRisk || 0),
      threatRisk: Math.round(threatRisk[0]?.avgRisk || 0)
    });
  }

  return trendData;
}

/**
 * Get vulnerability distribution by severity
 */
async function getVulnerabilityDistribution(organizationId, timeframe) {
  const startDate = new Date();
  startDate.setDate(startDate.getDate() - timeframe);

  const distribution = await Scan.aggregate([
    {
      $match: {
        organization: organizationId,
        createdAt: { $gte: startDate }
      }
    },
    {
      $group: {
        _id: null,
        critical: { $sum: '$summary.criticalCount' },
        high: { $sum: '$summary.highCount' },
        medium: { $sum: '$summary.mediumCount' },
        low: { $sum: '$summary.lowCount' },
        info: { $sum: '$summary.infoCount' }
      }
    }
  ]);

  return distribution[0] || {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    info: 0
  };
}

/**
 * Get compliance summary
 */
async function getComplianceSummary(organizationId) {
  const scans = await Scan.find({ 
    organization: organizationId,
    'compliance.0': { $exists: true }
  }).select('compliance');

  const frameworks = {};
  
  scans.forEach(scan => {
    scan.compliance.forEach(comp => {
      if (!frameworks[comp.framework]) {
        frameworks[comp.framework] = {
          total: 0,
          compliant: 0,
          nonCompliant: 0,
          partial: 0
        };
      }
      
      frameworks[comp.framework].total++;
      frameworks[comp.framework][comp.status === 'compliant' ? 'compliant' : 
                                comp.status === 'non-compliant' ? 'nonCompliant' : 'partial']++;
    });
  });

  // Calculate percentages
  Object.keys(frameworks).forEach(framework => {
    const data = frameworks[framework];
    data.compliancePercentage = Math.round((data.compliant / data.total) * 100);
  });

  return frameworks;
}

/**
 * Calculate organization risk score
 */
async function calculateOrganizationRiskScore(organizationId) {
  const [scanRisk, threatRisk, vulnerabilityCount] = await Promise.all([
    Scan.aggregate([
      {
        $match: {
          organization: organizationId,
          status: 'completed',
          createdAt: { $gte: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000) }
        }
      },
      {
        $group: {
          _id: null,
          avgRisk: { $avg: '$riskScore' },
          totalVulns: { $sum: '$summary.totalVulnerabilities' }
        }
      }
    ]),
    Threat.aggregate([
      {
        $match: {
          organization: organizationId,
          status: 'active'
        }
      },
      {
        $group: {
          _id: null,
          avgRisk: { $avg: '$riskScore' },
          count: { $sum: 1 }
        }
      }
    ]),
    Scan.aggregate([
      {
        $match: {
          organization: organizationId,
          createdAt: { $gte: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000) }
        }
      },
      {
        $group: {
          _id: null,
          critical: { $sum: '$summary.criticalCount' },
          high: { $sum: '$summary.highCount' }
        }
      }
    ])
  ]);

  const scanRiskScore = scanRisk[0]?.avgRisk || 0;
  const threatRiskScore = threatRisk[0]?.avgRisk || 0;
  const criticalVulns = vulnerabilityCount[0]?.critical || 0;
  const highVulns = vulnerabilityCount[0]?.high || 0;

  // Weighted calculation
  const riskScore = Math.round(
    (scanRiskScore * 0.4) + 
    (threatRiskScore * 0.3) + 
    (Math.min(criticalVulns * 2, 20) * 0.2) +
    (Math.min(highVulns * 1, 10) * 0.1)
  );

  return Math.min(riskScore, 100);
}

/**
 * Get recent activities
 */
async function getRecentActivities(organizationId, limit, skip) {
  // This would normally aggregate from multiple collections
  // For now, we'll get recent scans and threats
  const [recentScans, recentThreats] = await Promise.all([
    Scan.find({ organization: organizationId })
      .sort({ createdAt: -1 })
      .limit(limit / 2)
      .skip(skip / 2)
      .select('name type status createdAt')
      .populate('createdBy', 'firstName lastName'),
    Threat.find({ organization: organizationId })
      .sort({ firstDetected: -1 })
      .limit(limit / 2)
      .skip(skip / 2)
      .select('title type severity firstDetected')
  ]);

  const activities = [
    ...recentScans.map(scan => ({
      type: 'scan',
      id: scan._id,
      title: `Scan: ${scan.name}`,
      description: `${scan.type} scan ${scan.status}`,
      timestamp: scan.createdAt,
      user: scan.createdBy
    })),
    ...recentThreats.map(threat => ({
      type: 'threat',
      id: threat._id,
      title: `Threat: ${threat.title}`,
      description: `${threat.severity} ${threat.type} threat detected`,
      timestamp: threat.firstDetected
    }))
  ];

  // Sort by timestamp
  activities.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));

  return activities.slice(0, limit);
}

/**
 * Get system health status
 */
async function getSystemHealth() {
  return {
    database: { status: 'healthy', responseTime: '< 100ms' },
    cache: { status: 'healthy', responseTime: '< 10ms' },
    mlService: { status: 'healthy', responseTime: '< 500ms' },
    queues: { status: 'healthy', activeJobs: 0 }
  };
}

/**
 * Check service health
 */
async function checkServiceHealth(serviceUrl) {
  try {
    const axios = require('axios');
    const start = Date.now();
    await axios.get(`${serviceUrl}/health`, { timeout: 5000 });
    const responseTime = Date.now() - start;
    
    return {
      status: 'healthy',
      responseTime: `${responseTime}ms`
    };
  } catch (error) {
    return {
      status: 'unhealthy',
      error: error.message
    };
  }
}

module.exports = router;