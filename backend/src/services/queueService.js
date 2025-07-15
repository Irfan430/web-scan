/**
 * Queue Service
 * Handles background job processing using Bull queue system
 */

const Bull = require('bull');
const { getRedisClient } = require('../config/redis');
const logger = require('../config/logger');

class QueueService {
  constructor() {
    this.queues = {};
    this.redisClient = null;
    this.initialized = false;
  }

  /**
   * Initialize queue service with Redis connection
   */
  async initialize() {
    try {
      this.redisClient = getRedisClient();
      
      // Create queues for different job types
      this.createQueues();
      
      // Setup job processors
      this.setupProcessors();
      
      // Setup queue event listeners
      this.setupEventListeners();
      
      this.initialized = true;
      logger.info('🔄 Queue service initialized successfully');
    } catch (error) {
      logger.error('Failed to initialize queue service:', error);
      throw error;
    }
  }

  /**
   * Create Bull queues for different job types
   */
  createQueues() {
    const redisConfig = {
      redis: {
        host: process.env.REDIS_HOST || 'localhost',
        port: process.env.REDIS_PORT || 6379,
        password: process.env.REDIS_PASSWORD,
        db: process.env.REDIS_DB || 0,
      },
      defaultJobOptions: {
        removeOnComplete: 100, // Keep 100 completed jobs
        removeOnFail: 50, // Keep 50 failed jobs
        attempts: 3,
        backoff: {
          type: 'exponential',
          delay: 2000,
        },
      },
    };

    // Vulnerability scanning queue
    this.queues.scans = new Bull('vulnerability-scans', redisConfig);
    
    // Threat intelligence collection queue
    this.queues.threatIntel = new Bull('threat-intelligence', redisConfig);
    
    // Report generation queue
    this.queues.reports = new Bull('report-generation', redisConfig);
    
    // Notification queue
    this.queues.notifications = new Bull('notifications', redisConfig);
    
    // Email queue
    this.queues.emails = new Bull('email-sending', redisConfig);
    
    // Data cleanup queue
    this.queues.cleanup = new Bull('data-cleanup', redisConfig);
    
    // SOC automation queue
    this.queues.socAutomation = new Bull('soc-automation', redisConfig);
    
    // MITRE ATT&CK analysis queue
    this.queues.mitreAnalysis = new Bull('mitre-analysis', redisConfig);
    
    logger.info('📋 Bull queues created successfully');
  }

  /**
   * Setup job processors for each queue
   */
  setupProcessors() {
    // Vulnerability scan processor
    this.queues.scans.process('nmap-scan', require('./processors/nmapProcessor'));
    this.queues.scans.process('nikto-scan', require('./processors/niktoProcessor'));
    this.queues.scans.process('custom-scan', require('./processors/customScanProcessor'));
    this.queues.scans.process('brute-force', require('./processors/bruteForceProcessor'));

    // Threat intelligence processor
    this.queues.threatIntel.process('cve-feed', require('./processors/cveFeedProcessor'));
    this.queues.threatIntel.process('darkweb-crawl', require('./processors/darkwebCrawlProcessor'));
    this.queues.threatIntel.process('ioc-enrichment', require('./processors/iocEnrichmentProcessor'));
    this.queues.threatIntel.process('osint-collection', require('./processors/osintProcessor'));

    // Report generation processor
    this.queues.reports.process('pdf-report', require('./processors/pdfReportProcessor'));
    this.queues.reports.process('html-report', require('./processors/htmlReportProcessor'));
    this.queues.reports.process('executive-report', require('./processors/executiveReportProcessor'));
    this.queues.reports.process('compliance-report', require('./processors/complianceReportProcessor'));

    // Notification processor
    this.queues.notifications.process('slack-notification', require('./processors/slackNotificationProcessor'));
    this.queues.notifications.process('telegram-notification', require('./processors/telegramNotificationProcessor'));
    this.queues.notifications.process('jira-ticket', require('./processors/jiraTicketProcessor'));

    // Email processor
    this.queues.emails.process('alert-email', require('./processors/emailProcessor'));
    this.queues.emails.process('phishing-simulation', require('./processors/phishingEmailProcessor'));
    this.queues.emails.process('report-email', require('./processors/reportEmailProcessor'));

    // Data cleanup processor
    this.queues.cleanup.process('old-scans', require('./processors/cleanupProcessor'));
    this.queues.cleanup.process('log-rotation', require('./processors/logRotationProcessor'));
    this.queues.cleanup.process('temp-files', require('./processors/tempFileCleanupProcessor'));

    // SOC automation processor
    this.queues.socAutomation.process('incident-response', require('./processors/incidentResponseProcessor'));
    this.queues.socAutomation.process('threat-containment', require('./processors/threatContainmentProcessor'));
    this.queues.socAutomation.process('playbook-execution', require('./processors/playbookProcessor'));

    // MITRE ATT&CK analysis processor
    this.queues.mitreAnalysis.process('technique-mapping', require('./processors/mitreMappingProcessor'));
    this.queues.mitreAnalysis.process('heatmap-update', require('./processors/heatmapProcessor'));

    logger.info('⚙️ Queue processors registered successfully');
  }

  /**
   * Setup event listeners for queue monitoring
   */
  setupEventListeners() {
    Object.keys(this.queues).forEach(queueName => {
      const queue = this.queues[queueName];

      queue.on('completed', (job, result) => {
        logger.info(`Job completed in ${queueName}`, {
          jobId: job.id,
          jobType: job.name,
          duration: Date.now() - job.timestamp,
          result: typeof result === 'object' ? JSON.stringify(result) : result
        });
      });

      queue.on('failed', (job, err) => {
        logger.error(`Job failed in ${queueName}`, {
          jobId: job.id,
          jobType: job.name,
          error: err.message,
          attempts: job.attemptsMade,
          data: job.data
        });
      });

      queue.on('stalled', (job) => {
        logger.warn(`Job stalled in ${queueName}`, {
          jobId: job.id,
          jobType: job.name,
          attempts: job.attemptsMade
        });
      });

      queue.on('progress', (job, progress) => {
        logger.debug(`Job progress in ${queueName}`, {
          jobId: job.id,
          jobType: job.name,
          progress: progress
        });
      });
    });
  }

  /**
   * Add vulnerability scan job
   * @param {string} scanType - Type of scan (nmap, nikto, custom, brute-force)
   * @param {Object} data - Scan data
   * @param {Object} options - Job options
   * @returns {Promise<Object>} Job instance
   */
  async addScanJob(scanType, data, options = {}) {
    if (!this.initialized) {
      throw new Error('Queue service not initialized');
    }

    const jobOptions = {
      priority: options.priority || 5,
      delay: options.delay || 0,
      attempts: options.attempts || 3,
      ...options
    };

    try {
      const job = await this.queues.scans.add(scanType, data, jobOptions);
      
      logger.info('Scan job added to queue', {
        jobId: job.id,
        scanType: scanType,
        target: data.target,
        organizationId: data.organizationId
      });

      return job;
    } catch (error) {
      logger.error('Failed to add scan job to queue:', error);
      throw error;
    }
  }

  /**
   * Add threat intelligence collection job
   * @param {string} intelType - Type of intelligence (cve-feed, darkweb-crawl, ioc-enrichment, osint-collection)
   * @param {Object} data - Intelligence data
   * @param {Object} options - Job options
   * @returns {Promise<Object>} Job instance
   */
  async addThreatIntelJob(intelType, data, options = {}) {
    if (!this.initialized) {
      throw new Error('Queue service not initialized');
    }

    try {
      const job = await this.queues.threatIntel.add(intelType, data, options);
      
      logger.info('Threat intelligence job added to queue', {
        jobId: job.id,
        intelType: intelType,
        organizationId: data.organizationId
      });

      return job;
    } catch (error) {
      logger.error('Failed to add threat intelligence job to queue:', error);
      throw error;
    }
  }

  /**
   * Add report generation job
   * @param {string} reportType - Type of report (pdf, html, executive, compliance)
   * @param {Object} data - Report data
   * @param {Object} options - Job options
   * @returns {Promise<Object>} Job instance
   */
  async addReportJob(reportType, data, options = {}) {
    if (!this.initialized) {
      throw new Error('Queue service not initialized');
    }

    try {
      const job = await this.queues.reports.add(reportType, data, options);
      
      logger.info('Report generation job added to queue', {
        jobId: job.id,
        reportType: reportType,
        organizationId: data.organizationId
      });

      return job;
    } catch (error) {
      logger.error('Failed to add report job to queue:', error);
      throw error;
    }
  }

  /**
   * Add notification job
   * @param {string} notificationType - Type of notification (slack, telegram, jira)
   * @param {Object} data - Notification data
   * @param {Object} options - Job options
   * @returns {Promise<Object>} Job instance
   */
  async addNotificationJob(notificationType, data, options = {}) {
    if (!this.initialized) {
      throw new Error('Queue service not initialized');
    }

    try {
      const job = await this.queues.notifications.add(notificationType, data, options);
      
      logger.info('Notification job added to queue', {
        jobId: job.id,
        notificationType: notificationType,
        recipient: data.recipient || data.channel
      });

      return job;
    } catch (error) {
      logger.error('Failed to add notification job to queue:', error);
      throw error;
    }
  }

  /**
   * Add email job
   * @param {string} emailType - Type of email (alert, phishing-simulation, report)
   * @param {Object} data - Email data
   * @param {Object} options - Job options
   * @returns {Promise<Object>} Job instance
   */
  async addEmailJob(emailType, data, options = {}) {
    if (!this.initialized) {
      throw new Error('Queue service not initialized');
    }

    try {
      const job = await this.queues.emails.add(emailType, data, options);
      
      logger.info('Email job added to queue', {
        jobId: job.id,
        emailType: emailType,
        recipient: data.to
      });

      return job;
    } catch (error) {
      logger.error('Failed to add email job to queue:', error);
      throw error;
    }
  }

  /**
   * Schedule recurring cleanup jobs
   */
  async scheduleCleanupJobs() {
    // Clean old scans daily at 2 AM
    await this.queues.cleanup.add('old-scans', {}, {
      repeat: { cron: '0 2 * * *' }
    });

    // Rotate logs daily at 3 AM
    await this.queues.cleanup.add('log-rotation', {}, {
      repeat: { cron: '0 3 * * *' }
    });

    // Clean temporary files every 6 hours
    await this.queues.cleanup.add('temp-files', {}, {
      repeat: { cron: '0 */6 * * *' }
    });

    logger.info('📅 Recurring cleanup jobs scheduled');
  }

  /**
   * Schedule recurring threat intelligence jobs
   */
  async scheduleThreatIntelJobs() {
    // Update CVE feed every hour
    await this.queues.threatIntel.add('cve-feed', {}, {
      repeat: { cron: '0 * * * *' }
    });

    // OSINT collection every 4 hours
    await this.queues.threatIntel.add('osint-collection', {}, {
      repeat: { cron: '0 */4 * * *' }
    });

    logger.info('🔍 Recurring threat intelligence jobs scheduled');
  }

  /**
   * Get queue statistics
   * @param {string} queueName - Queue name
   * @returns {Promise<Object>} Queue statistics
   */
  async getQueueStats(queueName) {
    if (!this.queues[queueName]) {
      throw new Error(`Queue ${queueName} not found`);
    }

    const queue = this.queues[queueName];
    const [waiting, active, completed, failed, delayed] = await Promise.all([
      queue.getWaiting(),
      queue.getActive(),
      queue.getCompleted(),
      queue.getFailed(),
      queue.getDelayed(),
    ]);

    return {
      waiting: waiting.length,
      active: active.length,
      completed: completed.length,
      failed: failed.length,
      delayed: delayed.length,
      total: waiting.length + active.length + completed.length + failed.length + delayed.length
    };
  }

  /**
   * Get all queue statistics
   * @returns {Promise<Object>} All queue statistics
   */
  async getAllQueueStats() {
    const stats = {};
    
    for (const queueName of Object.keys(this.queues)) {
      stats[queueName] = await this.getQueueStats(queueName);
    }

    return stats;
  }

  /**
   * Pause a queue
   * @param {string} queueName - Queue name
   */
  async pauseQueue(queueName) {
    if (!this.queues[queueName]) {
      throw new Error(`Queue ${queueName} not found`);
    }

    await this.queues[queueName].pause();
    logger.info(`Queue ${queueName} paused`);
  }

  /**
   * Resume a queue
   * @param {string} queueName - Queue name
   */
  async resumeQueue(queueName) {
    if (!this.queues[queueName]) {
      throw new Error(`Queue ${queueName} not found`);
    }

    await this.queues[queueName].resume();
    logger.info(`Queue ${queueName} resumed`);
  }

  /**
   * Clean completed jobs from queue
   * @param {string} queueName - Queue name
   * @param {number} grace - Grace period in milliseconds
   */
  async cleanQueue(queueName, grace = 0) {
    if (!this.queues[queueName]) {
      throw new Error(`Queue ${queueName} not found`);
    }

    await this.queues[queueName].clean(grace, 'completed');
    await this.queues[queueName].clean(grace, 'failed');
    
    logger.info(`Queue ${queueName} cleaned`);
  }

  /**
   * Close all queues
   */
  async close() {
    const closePromises = Object.values(this.queues).map(queue => queue.close());
    await Promise.all(closePromises);
    
    this.initialized = false;
    logger.info('🔄 Queue service closed');
  }
}

module.exports = QueueService;