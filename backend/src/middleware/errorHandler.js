/**
 * Global Error Handler Middleware
 * Handles all errors in the application with proper logging and user-friendly responses
 */

const logger = require('../config/logger');

/**
 * Development error response
 * @param {Error} err - Error object
 * @param {Object} res - Express response object
 */
const sendErrorDev = (err, res) => {
  const statusCode = err.statusCode || 500;
  const status = err.status || 'error';

  res.status(statusCode).json({
    success: false,
    status,
    error: {
      message: err.message,
      stack: err.stack,
      name: err.name,
      statusCode,
      isOperational: err.isOperational || false
    },
    request: {
      method: res.req.method,
      url: res.req.originalUrl,
      timestamp: new Date().toISOString()
    }
  });
};

/**
 * Production error response
 * @param {Error} err - Error object
 * @param {Object} res - Express response object
 */
const sendErrorProd = (err, res) => {
  const statusCode = err.statusCode || 500;
  
  // Operational errors: send message to client
  if (err.isOperational) {
    res.status(statusCode).json({
      success: false,
      message: err.message,
      code: err.code || 'INTERNAL_ERROR',
      timestamp: new Date().toISOString()
    });
  } else {
    // Programming errors: don't leak error details
    logger.error('Programming Error:', err);
    
    res.status(500).json({
      success: false,
      message: 'Something went wrong on our end. Please try again later.',
      code: 'INTERNAL_SERVER_ERROR',
      timestamp: new Date().toISOString()
    });
  }
};

/**
 * Handle Cast Error (Invalid MongoDB ObjectId)
 * @param {Error} err - Cast error
 * @returns {Error} Formatted error
 */
const handleCastErrorDB = (err) => {
  const message = `Invalid ${err.path}: ${err.value}`;
  const error = new Error(message);
  error.statusCode = 400;
  error.isOperational = true;
  error.code = 'INVALID_ID';
  return error;
};

/**
 * Handle Duplicate Field Error (MongoDB 11000)
 * @param {Error} err - Duplicate error
 * @returns {Error} Formatted error
 */
const handleDuplicateFieldsDB = (err) => {
  const field = Object.keys(err.keyValue)[0];
  const value = err.keyValue[field];
  const message = `${field.charAt(0).toUpperCase() + field.slice(1)} '${value}' already exists`;
  
  const error = new Error(message);
  error.statusCode = 400;
  error.isOperational = true;
  error.code = 'DUPLICATE_FIELD';
  error.field = field;
  return error;
};

/**
 * Handle Validation Error (Mongoose)
 * @param {Error} err - Validation error
 * @returns {Error} Formatted error
 */
const handleValidationErrorDB = (err) => {
  const errors = Object.values(err.errors).map(el => el.message);
  const message = `Invalid input data: ${errors.join('. ')}`;
  
  const error = new Error(message);
  error.statusCode = 400;
  error.isOperational = true;
  error.code = 'VALIDATION_ERROR';
  error.validationErrors = errors;
  return error;
};

/**
 * Handle JWT Invalid Error
 * @returns {Error} Formatted error
 */
const handleJWTError = () => {
  const error = new Error('Invalid token. Please log in again.');
  error.statusCode = 401;
  error.isOperational = true;
  error.code = 'INVALID_TOKEN';
  return error;
};

/**
 * Handle JWT Expired Error
 * @returns {Error} Formatted error
 */
const handleJWTExpiredError = () => {
  const error = new Error('Your token has expired. Please log in again.');
  error.statusCode = 401;
  error.isOperational = true;
  error.code = 'EXPIRED_TOKEN';
  return error;
};

/**
 * Handle Multer File Upload Errors
 * @param {Error} err - Multer error
 * @returns {Error} Formatted error
 */
const handleMulterError = (err) => {
  let message = 'File upload error';
  let code = 'FILE_UPLOAD_ERROR';

  switch (err.code) {
    case 'LIMIT_FILE_SIZE':
      message = 'File too large. Maximum size allowed is 50MB';
      code = 'FILE_TOO_LARGE';
      break;
    case 'LIMIT_FILE_COUNT':
      message = 'Too many files. Maximum 10 files allowed';
      code = 'TOO_MANY_FILES';
      break;
    case 'LIMIT_UNEXPECTED_FILE':
      message = 'Unexpected file field';
      code = 'UNEXPECTED_FILE';
      break;
    case 'LIMIT_FIELD_KEY':
      message = 'Field name too long';
      code = 'FIELD_NAME_TOO_LONG';
      break;
    case 'LIMIT_FIELD_VALUE':
      message = 'Field value too long';
      code = 'FIELD_VALUE_TOO_LONG';
      break;
    case 'LIMIT_FIELD_COUNT':
      message = 'Too many fields';
      code = 'TOO_MANY_FIELDS';
      break;
    case 'LIMIT_PART_COUNT':
      message = 'Too many parts in multipart data';
      code = 'TOO_MANY_PARTS';
      break;
    default:
      message = err.message || 'File upload error';
  }

  const error = new Error(message);
  error.statusCode = 400;
  error.isOperational = true;
  error.code = code;
  return error;
};

/**
 * Handle Redis Connection Errors
 * @param {Error} err - Redis error
 * @returns {Error} Formatted error
 */
const handleRedisError = (err) => {
  const error = new Error('Cache service temporarily unavailable');
  error.statusCode = 503;
  error.isOperational = true;
  error.code = 'CACHE_UNAVAILABLE';
  return error;
};

/**
 * Handle Rate Limit Errors
 * @param {Error} err - Rate limit error
 * @returns {Error} Formatted error
 */
const handleRateLimitError = (err) => {
  const error = new Error('Too many requests. Please try again later.');
  error.statusCode = 429;
  error.isOperational = true;
  error.code = 'RATE_LIMIT_EXCEEDED';
  error.retryAfter = err.retryAfter || 900; // 15 minutes default
  return error;
};

/**
 * Main error handling middleware
 * @param {Error} err - Error object
 * @param {Object} req - Express request object
 * @param {Object} res - Express response object
 * @param {Function} next - Express next function
 */
const globalErrorHandler = (err, req, res, next) => {
  // Set default error properties
  err.statusCode = err.statusCode || 500;
  err.status = err.status || 'error';

  // Log error details
  const errorLog = {
    message: err.message,
    stack: err.stack,
    statusCode: err.statusCode,
    status: err.status,
    isOperational: err.isOperational || false,
    method: req.method,
    url: req.originalUrl,
    ip: req.ip,
    userAgent: req.get('User-Agent'),
    userId: req.user ? req.user._id : null,
    timestamp: new Date().toISOString()
  };

  // Log based on severity
  if (err.statusCode >= 500) {
    logger.error('Server Error:', errorLog);
  } else if (err.statusCode >= 400) {
    logger.warn('Client Error:', errorLog);
  } else {
    logger.info('Request Error:', errorLog);
  }

  // Security logging for certain errors
  if (err.statusCode === 401 || err.statusCode === 403) {
    logger.security('Security Event:', {
      type: 'access_denied',
      statusCode: err.statusCode,
      message: err.message,
      ...errorLog
    });
  }

  let error = { ...err };
  error.message = err.message;

  // Handle specific error types
  if (err.name === 'CastError') {
    error = handleCastErrorDB(error);
  } else if (err.code === 11000) {
    error = handleDuplicateFieldsDB(error);
  } else if (err.name === 'ValidationError') {
    error = handleValidationErrorDB(error);
  } else if (err.name === 'JsonWebTokenError') {
    error = handleJWTError();
  } else if (err.name === 'TokenExpiredError') {
    error = handleJWTExpiredError();
  } else if (err.code && err.code.startsWith('LIMIT_')) {
    error = handleMulterError(error);
  } else if (err.code === 'ECONNREFUSED' && err.port === 6379) {
    error = handleRedisError(error);
  } else if (err.statusCode === 429) {
    error = handleRateLimitError(error);
  }

  // Send error response
  if (process.env.NODE_ENV === 'development') {
    sendErrorDev(error, res);
  } else {
    sendErrorProd(error, res);
  }
};

/**
 * Handle 404 errors for undefined routes
 * @param {Object} req - Express request object
 * @param {Object} res - Express response object
 * @param {Function} next - Express next function
 */
const notFoundHandler = (req, res, next) => {
  const message = `Can't find ${req.originalUrl} on this server!`;
  const error = new Error(message);
  error.statusCode = 404;
  error.isOperational = true;
  error.code = 'ROUTE_NOT_FOUND';
  
  logger.warn('Route not found:', {
    method: req.method,
    url: req.originalUrl,
    ip: req.ip,
    userAgent: req.get('User-Agent'),
    userId: req.user ? req.user._id : null
  });
  
  next(error);
};

/**
 * Async error wrapper to catch async errors
 * @param {Function} fn - Async function to wrap
 * @returns {Function} Wrapped function
 */
const catchAsync = (fn) => {
  return (req, res, next) => {
    fn(req, res, next).catch(next);
  };
};

/**
 * Create operational error
 * @param {string} message - Error message
 * @param {number} statusCode - HTTP status code
 * @param {string} code - Error code
 * @returns {Error} Operational error
 */
const createError = (message, statusCode = 500, code = 'INTERNAL_ERROR') => {
  const error = new Error(message);
  error.statusCode = statusCode;
  error.isOperational = true;
  error.code = code;
  return error;
};

module.exports = {
  globalErrorHandler,
  notFoundHandler,
  catchAsync,
  createError
};