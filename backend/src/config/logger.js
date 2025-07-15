/**
 * Winston Logger Configuration
 * Provides comprehensive logging with file rotation and different log levels
 */

const winston = require('winston');
const DailyRotateFile = require('winston-daily-rotate-file');
const path = require('path');
const fs = require('fs');

// Create logs directory if it doesn't exist
const logsDir = path.join(process.cwd(), 'logs');
if (!fs.existsSync(logsDir)) {
  fs.mkdirSync(logsDir, { recursive: true });
}

// Custom log format
const logFormat = winston.format.combine(
  winston.format.timestamp({
    format: 'YYYY-MM-DD HH:mm:ss'
  }),
  winston.format.errors({ stack: true }),
  winston.format.json(),
  winston.format.prettyPrint()
);

// Console format for development
const consoleFormat = winston.format.combine(
  winston.format.colorize(),
  winston.format.timestamp({
    format: 'HH:mm:ss'
  }),
  winston.format.printf(({ timestamp, level, message, ...meta }) => {
    let msg = `${timestamp} [${level}]: ${message}`;
    
    // Add metadata if present
    if (Object.keys(meta).length > 0) {
      msg += ` ${JSON.stringify(meta, null, 2)}`;
    }
    
    return msg;
  })
);

// Transport configurations
const transports = [];

// Console transport (always enabled in development)
if (process.env.NODE_ENV === 'development') {
  transports.push(
    new winston.transports.Console({
      format: consoleFormat,
      level: 'debug'
    })
  );
} else {
  transports.push(
    new winston.transports.Console({
      format: winston.format.combine(
        winston.format.timestamp(),
        winston.format.json()
      ),
      level: 'info'
    })
  );
}

// File transport for all logs
transports.push(
  new DailyRotateFile({
    filename: path.join(logsDir, 'application-%DATE%.log'),
    datePattern: 'YYYY-MM-DD',
    maxSize: '20m',
    maxFiles: '14d',
    format: logFormat,
    level: 'info'
  })
);

// File transport for error logs only
transports.push(
  new DailyRotateFile({
    filename: path.join(logsDir, 'error-%DATE%.log'),
    datePattern: 'YYYY-MM-DD',
    maxSize: '20m',
    maxFiles: '30d',
    format: logFormat,
    level: 'error'
  })
);

// File transport for security logs
transports.push(
  new DailyRotateFile({
    filename: path.join(logsDir, 'security-%DATE%.log'),
    datePattern: 'YYYY-MM-DD',
    maxSize: '20m',
    maxFiles: '90d',
    format: logFormat,
    level: 'warn'
  })
);

// Create logger instance
const logger = winston.createLogger({
  level: process.env.LOG_LEVEL || 'info',
  format: logFormat,
  defaultMeta: {
    service: 'cybersec-platform',
    environment: process.env.NODE_ENV || 'development',
    version: process.env.npm_package_version || '1.0.0'
  },
  transports,
  // Handle exceptions and rejections
  exceptionHandlers: [
    new DailyRotateFile({
      filename: path.join(logsDir, 'exceptions-%DATE%.log'),
      datePattern: 'YYYY-MM-DD',
      maxSize: '20m',
      maxFiles: '30d',
      format: logFormat
    })
  ],
  rejectionHandlers: [
    new DailyRotateFile({
      filename: path.join(logsDir, 'rejections-%DATE%.log'),
      datePattern: 'YYYY-MM-DD',
      maxSize: '20m',
      maxFiles: '30d',
      format: logFormat
    })
  ]
});

// Extend logger with custom methods
logger.security = (message, meta = {}) => {
  logger.warn(message, { ...meta, type: 'security' });
};

logger.audit = (message, meta = {}) => {
  logger.info(message, { ...meta, type: 'audit' });
};

logger.performance = (message, meta = {}) => {
  logger.info(message, { ...meta, type: 'performance' });
};

logger.api = (req, res, responseTime) => {
  const logData = {
    type: 'api',
    method: req.method,
    url: req.originalUrl,
    statusCode: res.statusCode,
    responseTime: `${responseTime}ms`,
    userAgent: req.get('User-Agent'),
    ip: req.ip || req.connection.remoteAddress,
    userId: req.user ? req.user.id : 'anonymous'
  };

  if (res.statusCode >= 400) {
    logger.warn(`API Error: ${req.method} ${req.originalUrl}`, logData);
  } else {
    logger.info(`API: ${req.method} ${req.originalUrl}`, logData);
  }
};

logger.scan = (scanType, target, status, meta = {}) => {
  logger.info(`Scan ${status}: ${scanType} on ${target}`, {
    type: 'scan',
    scanType,
    target,
    status,
    ...meta
  });
};

logger.threat = (threatType, severity, source, meta = {}) => {
  const logLevel = severity === 'critical' || severity === 'high' ? 'error' : 'warn';
  logger[logLevel](`Threat Detected: ${threatType}`, {
    type: 'threat',
    threatType,
    severity,
    source,
    ...meta
  });
};

logger.auth = (action, userId, success, meta = {}) => {
  const message = `Auth ${action}: ${success ? 'Success' : 'Failed'} for user ${userId}`;
  if (success) {
    logger.info(message, { type: 'auth', action, userId, success, ...meta });
  } else {
    logger.security(message, { type: 'auth', action, userId, success, ...meta });
  }
};

logger.billing = (action, userId, amount, meta = {}) => {
  logger.info(`Billing ${action}: $${amount} for user ${userId}`, {
    type: 'billing',
    action,
    userId,
    amount,
    ...meta
  });
};

// Log startup information
logger.info('🚀 Logger initialized', {
  type: 'system',
  logLevel: logger.level,
  nodeEnv: process.env.NODE_ENV,
  logsDir: logsDir
});

// Handle transport events
transports.forEach(transport => {
  if (transport instanceof DailyRotateFile) {
    transport.on('rotate', (oldFilename, newFilename) => {
      logger.info(`Log file rotated: ${oldFilename} -> ${newFilename}`, {
        type: 'system'
      });
    });

    transport.on('archive', (zipFilename) => {
      logger.info(`Log file archived: ${zipFilename}`, {
        type: 'system'
      });
    });

    transport.on('logRemoved', (removedFilename) => {
      logger.info(`Old log file removed: ${removedFilename}`, {
        type: 'system'
      });
    });
  }
});

// Performance monitoring middleware
logger.performanceMiddleware = () => {
  return (req, res, next) => {
    const start = Date.now();
    
    res.on('finish', () => {
      const responseTime = Date.now() - start;
      logger.api(req, res, responseTime);
      
      // Log slow requests
      if (responseTime > 1000) {
        logger.performance(`Slow request detected: ${req.method} ${req.originalUrl}`, {
          responseTime,
          url: req.originalUrl,
          method: req.method
        });
      }
    });
    
    next();
  };
};

module.exports = logger;