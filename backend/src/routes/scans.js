/**
 * Scan Routes
 * Handles vulnerability scanning operations including creation, execution, and management
 */

const express = require('express');
const { body, validationResult, query } = require('express-validator');
const { authenticate, authorize, checkFeatureAccess, checkOrganizationAccess } = require('../middleware/auth');
const { catchAsync, createError } = require('../middleware/errorHandler');
const Scan = require('../models/Scan');
const Organization = require('../models/Organization');
const logger = require('../config/logger');

const router = express.Router();

/**
 * @swagger
 * /api/scans:
 *   get:
 *     summary: Get scans for organization
 *     tags: [Scans]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: query
 *         name: page
 *         schema:
 *           type: integer
 *           default: 1
 *       - in: query
 *         name: limit
 *         schema:
 *           type: integer
 *           default: 20
 *       - in: query
 *         name: status
 *         schema:
 *           type: string
 *           enum: [pending, queued, running, paused, completed, failed, cancelled]
 *       - in: query
 *         name: type
 *         schema:
 *           type: string
 *           enum: [nmap, nikto, custom, brute-force, web-app, network, compliance]
 */
router.get('/', authenticate, [
  query('page').optional().isInt({ min: 1 }),
  query('limit').optional().isInt({ min: 1, max: 100 }),
  query('status').optional().isIn(['pending', 'queued', 'running', 'paused', 'completed', 'failed', 'cancelled']),
  query('type').optional().isIn(['nmap', 'nikto', 'custom', 'brute-force', 'web-app', 'network', 'compliance'])
], catchAsync(async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({
      success: false,
      message: 'Validation failed',
      errors: errors.array()
    });
  }

  const organizationId = req.user.organization._id;
  const page = parseInt(req.query.page) || 1;
  const limit = parseInt(req.query.limit) || 20;
  const skip = (page - 1) * limit;

  // Build filter
  const filter = { organization: organizationId };
  if (req.query.status) filter.status = req.query.status;
  if (req.query.type) filter.type = req.query.type;
  if (req.query.search) {
    filter.$or = [
      { name: { $regex: req.query.search, $options: 'i' } },
      { description: { $regex: req.query.search, $options: 'i' } }
    ];
  }

  const [scans, total] = await Promise.all([
    Scan.find(filter)
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(limit)
      .populate('createdBy', 'firstName lastName email')
      .populate('assignedTo', 'firstName lastName email')
      .select('-rawOutput -xmlOutput -jsonOutput'), // Exclude large fields
    Scan.countDocuments(filter)
  ]);

  res.json({
    success: true,
    data: {
      scans: scans,
      pagination: {
        page: page,
        limit: limit,
        total: total,
        pages: Math.ceil(total / limit)
      }
    }
  });
}));

/**
 * @swagger
 * /api/scans/{id}:
 *   get:
 *     summary: Get scan by ID
 *     tags: [Scans]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 */
router.get('/:id', authenticate, catchAsync(async (req, res) => {
  const scan = await Scan.findOne({ 
    _id: req.params.id,
    organization: req.user.organization._id 
  })
    .populate('createdBy', 'firstName lastName email')
    .populate('assignedTo', 'firstName lastName email');

  if (!scan) {
    return res.status(404).json({
      success: false,
      message: 'Scan not found'
    });
  }

  res.json({
    success: true,
    data: { scan: scan }
  });
}));

/**
 * @swagger
 * /api/scans:
 *   post:
 *     summary: Create a new scan
 *     tags: [Scans]
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - name
 *               - type
 *               - targets
 *             properties:
 *               name:
 *                 type: string
 *               description:
 *                 type: string
 *               type:
 *                 type: string
 *                 enum: [nmap, nikto, custom, brute-force, web-app, network, compliance]
 *               targets:
 *                 type: array
 *                 items:
 *                   type: object
 *                   properties:
 *                     type:
 *                       type: string
 *                       enum: [ip, domain, url, range]
 *                     value:
 *                       type: string
 *                     ports:
 *                       type: array
 *                       items:
 *                         type: string
 */
router.post('/', authenticate, checkFeatureAccess(['basic_scans']), [
  body('name')
    .trim()
    .isLength({ min: 3, max: 100 })
    .withMessage('Scan name must be between 3 and 100 characters'),
  body('type')
    .isIn(['nmap', 'nikto', 'custom', 'brute-force', 'web-app', 'network', 'compliance'])
    .withMessage('Invalid scan type'),
  body('targets')
    .isArray({ min: 1 })
    .withMessage('At least one target is required'),
  body('targets.*.type')
    .isIn(['ip', 'domain', 'url', 'range'])
    .withMessage('Invalid target type'),
  body('targets.*.value')
    .trim()
    .notEmpty()
    .withMessage('Target value is required')
], catchAsync(async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({
      success: false,
      message: 'Validation failed',
      errors: errors.array()
    });
  }

  const organizationId = req.user.organization._id;
  const organization = await Organization.findById(organizationId);

  // Check scan limits
  if (organization.isLimitExceeded('scansPerMonth')) {
    return res.status(403).json({
      success: false,
      message: 'Monthly scan limit exceeded. Please upgrade your plan.',
      currentUsage: organization.usage.scansThisMonth,
      limit: organization.limits.scansPerMonth
    });
  }

  // Check target limits
  if (req.body.targets.length > organization.limits.targetsPerScan) {
    return res.status(403).json({
      success: false,
      message: `Too many targets. Maximum ${organization.limits.targetsPerScan} targets allowed per scan.`,
      currentTargets: req.body.targets.length,
      limit: organization.limits.targetsPerScan
    });
  }

  // Validate target formats
  for (const target of req.body.targets) {
    if (!isValidTarget(target)) {
      return res.status(400).json({
        success: false,
        message: `Invalid target format: ${target.value}`
      });
    }
  }

  const scanData = {
    ...req.body,
    organization: organizationId,
    createdBy: req.user._id,
    status: 'pending'
  };

  const scan = new Scan(scanData);
  await scan.save();

  // Increment organization usage
  await organization.incrementUsage('scansThisMonth');

  logger.scan(scan.type, scan.targets.map(t => t.value).join(', '), 'created', {
    scanId: scan._id,
    userId: req.user._id,
    organizationId: organizationId
  });

  res.status(201).json({
    success: true,
    message: 'Scan created successfully',
    data: { scan: scan }
  });

  // TODO: Add scan to queue for execution
  // await queueService.addScanJob(scan.type, {
  //   scanId: scan._id,
  //   organizationId: organizationId,
  //   targets: scan.targets,
  //   parameters: scan.parameters
  // });
}));

/**
 * @swagger
 * /api/scans/{id}/start:
 *   post:
 *     summary: Start a scan
 *     tags: [Scans]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 */
router.post('/:id/start', authenticate, authorize('analyst', 'manager', 'admin'), catchAsync(async (req, res) => {
  const scan = await Scan.findOne({
    _id: req.params.id,
    organization: req.user.organization._id
  });

  if (!scan) {
    return res.status(404).json({
      success: false,
      message: 'Scan not found'
    });
  }

  if (scan.status !== 'pending') {
    return res.status(400).json({
      success: false,
      message: `Cannot start scan in ${scan.status} status`
    });
  }

  // Update scan status
  scan.status = 'queued';
  scan.startedAt = new Date();
  await scan.save();

  logger.scan(scan.type, scan.targets.map(t => t.value).join(', '), 'started', {
    scanId: scan._id,
    userId: req.user._id
  });

  res.json({
    success: true,
    message: 'Scan started successfully',
    data: { scan: scan }
  });

  // TODO: Add to queue
  // await queueService.addScanJob(scan.type, { scanId: scan._id });
}));

/**
 * @swagger
 * /api/scans/{id}/pause:
 *   post:
 *     summary: Pause a running scan
 *     tags: [Scans]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 */
router.post('/:id/pause', authenticate, authorize('analyst', 'manager', 'admin'), catchAsync(async (req, res) => {
  const scan = await Scan.findOne({
    _id: req.params.id,
    organization: req.user.organization._id
  });

  if (!scan) {
    return res.status(404).json({
      success: false,
      message: 'Scan not found'
    });
  }

  if (scan.status !== 'running') {
    return res.status(400).json({
      success: false,
      message: `Cannot pause scan in ${scan.status} status`
    });
  }

  scan.status = 'paused';
  await scan.save();

  logger.scan(scan.type, scan.targets.map(t => t.value).join(', '), 'paused', {
    scanId: scan._id,
    userId: req.user._id
  });

  res.json({
    success: true,
    message: 'Scan paused successfully',
    data: { scan: scan }
  });
}));

/**
 * @swagger
 * /api/scans/{id}/cancel:
 *   post:
 *     summary: Cancel a scan
 *     tags: [Scans]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 */
router.post('/:id/cancel', authenticate, authorize('analyst', 'manager', 'admin'), catchAsync(async (req, res) => {
  const scan = await Scan.findOne({
    _id: req.params.id,
    organization: req.user.organization._id
  });

  if (!scan) {
    return res.status(404).json({
      success: false,
      message: 'Scan not found'
    });
  }

  if (!['pending', 'queued', 'running', 'paused'].includes(scan.status)) {
    return res.status(400).json({
      success: false,
      message: `Cannot cancel scan in ${scan.status} status`
    });
  }

  scan.status = 'cancelled';
  scan.completedAt = new Date();
  await scan.save();

  logger.scan(scan.type, scan.targets.map(t => t.value).join(', '), 'cancelled', {
    scanId: scan._id,
    userId: req.user._id
  });

  res.json({
    success: true,
    message: 'Scan cancelled successfully',
    data: { scan: scan }
  });
}));

/**
 * @swagger
 * /api/scans/{id}/results:
 *   get:
 *     summary: Get scan results
 *     tags: [Scans]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *       - in: query
 *         name: format
 *         schema:
 *           type: string
 *           enum: [json, xml, raw]
 */
router.get('/:id/results', authenticate, catchAsync(async (req, res) => {
  const scan = await Scan.findOne({
    _id: req.params.id,
    organization: req.user.organization._id
  });

  if (!scan) {
    return res.status(404).json({
      success: false,
      message: 'Scan not found'
    });
  }

  const format = req.query.format || 'json';

  switch (format) {
    case 'xml':
      res.set('Content-Type', 'application/xml');
      res.send(scan.xmlOutput || '<results>No XML output available</results>');
      break;
    case 'raw':
      res.set('Content-Type', 'text/plain');
      res.send(scan.rawOutput || 'No raw output available');
      break;
    default:
      res.json({
        success: true,
        data: {
          scan: {
            id: scan._id,
            name: scan.name,
            type: scan.type,
            status: scan.status,
            summary: scan.summary,
            vulnerabilities: scan.vulnerabilities,
            hosts: scan.hosts,
            compliance: scan.compliance,
            mitreMapping: scan.mitreMapping,
            duration: scan.duration,
            completedAt: scan.completedAt
          }
        }
      });
  }
}));

/**
 * @swagger
 * /api/scans/{id}/vulnerabilities:
 *   get:
 *     summary: Get scan vulnerabilities
 *     tags: [Scans]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *       - in: query
 *         name: severity
 *         schema:
 *           type: string
 *           enum: [critical, high, medium, low, info]
 */
router.get('/:id/vulnerabilities', authenticate, catchAsync(async (req, res) => {
  const scan = await Scan.findOne({
    _id: req.params.id,
    organization: req.user.organization._id
  }).select('vulnerabilities summary');

  if (!scan) {
    return res.status(404).json({
      success: false,
      message: 'Scan not found'
    });
  }

  let vulnerabilities = scan.vulnerabilities;

  // Filter by severity if specified
  if (req.query.severity) {
    vulnerabilities = vulnerabilities.filter(v => v.severity === req.query.severity);
  }

  // Filter out false positives by default
  if (req.query.includeFalsePositives !== 'true') {
    vulnerabilities = vulnerabilities.filter(v => !v.falsePositive);
  }

  res.json({
    success: true,
    data: {
      vulnerabilities: vulnerabilities,
      summary: scan.summary,
      totalCount: vulnerabilities.length
    }
  });
}));

/**
 * @swagger
 * /api/scans/{id}:
 *   delete:
 *     summary: Delete a scan
 *     tags: [Scans]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 */
router.delete('/:id', authenticate, authorize('manager', 'admin'), catchAsync(async (req, res) => {
  const scan = await Scan.findOne({
    _id: req.params.id,
    organization: req.user.organization._id
  });

  if (!scan) {
    return res.status(404).json({
      success: false,
      message: 'Scan not found'
    });
  }

  // Don't allow deletion of running scans
  if (['running', 'queued'].includes(scan.status)) {
    return res.status(400).json({
      success: false,
      message: 'Cannot delete a running or queued scan. Please cancel it first.'
    });
  }

  await Scan.findByIdAndDelete(req.params.id);

  logger.scan(scan.type, scan.targets.map(t => t.value).join(', '), 'deleted', {
    scanId: scan._id,
    userId: req.user._id
  });

  res.json({
    success: true,
    message: 'Scan deleted successfully'
  });
}));

/**
 * @swagger
 * /api/scans/templates:
 *   get:
 *     summary: Get scan templates
 *     tags: [Scans]
 *     security:
 *       - bearerAuth: []
 */
router.get('/templates', authenticate, catchAsync(async (req, res) => {
  const templates = [
    {
      id: 'quick-network-scan',
      name: 'Quick Network Scan',
      description: 'Fast network discovery and port scan',
      type: 'nmap',
      parameters: {
        scanType: 'quick',
        timeout: 300,
        maxThreads: 20
      },
      targets: [
        { type: 'range', value: '192.168.1.0/24', ports: ['22', '80', '443', '3389'] }
      ]
    },
    {
      id: 'web-app-security',
      name: 'Web Application Security Scan',
      description: 'Comprehensive web application vulnerability assessment',
      type: 'nikto',
      parameters: {
        scanType: 'comprehensive',
        timeout: 1800,
        maxThreads: 10
      },
      targets: [
        { type: 'url', value: 'https://example.com' }
      ]
    },
    {
      id: 'compliance-check',
      name: 'Compliance Assessment',
      description: 'Security compliance verification',
      type: 'compliance',
      parameters: {
        scanType: 'standard',
        timeout: 3600,
        frameworks: ['NIST', 'ISO27001']
      }
    }
  ];

  res.json({
    success: true,
    data: { templates: templates }
  });
}));

// Helper functions

/**
 * Validate target format
 */
function isValidTarget(target) {
  const { type, value } = target;
  
  switch (type) {
    case 'ip':
      return /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/.test(value);
    case 'range':
      return /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\/(?:[0-9]|[1-2][0-9]|3[0-2])$/.test(value);
    case 'domain':
      return /^[a-zA-Z0-9][a-zA-Z0-9-]{1,61}[a-zA-Z0-9]\.[a-zA-Z]{2,}$/.test(value);
    case 'url':
      try {
        new URL(value);
        return true;
      } catch {
        return false;
      }
    default:
      return false;
  }
}

module.exports = router;