/**
 * MongoDB Database Configuration
 * Handles connection to MongoDB with proper error handling and logging
 */

const mongoose = require('mongoose');
const logger = require('./logger');

/**
 * Connect to MongoDB database
 * @returns {Promise} MongoDB connection promise
 */
const connectDB = async () => {
  try {
    // MongoDB connection options
    const options = {
      useNewUrlParser: true,
      useUnifiedTopology: true,
      maxPoolSize: 10, // Maintain up to 10 socket connections
      serverSelectionTimeoutMS: 5000, // Keep trying to send operations for 5 seconds
      socketTimeoutMS: 45000, // Close sockets after 45 seconds of inactivity
      family: 4, // Use IPv4, skip trying IPv6
      retryWrites: true,
      w: 'majority',
    };

    // Connect to MongoDB
    const conn = await mongoose.connect(process.env.MONGODB_URI, options);

    logger.info(`✅ MongoDB Connected: ${conn.connection.host}`);
    logger.info(`📊 Database: ${conn.connection.name}`);
    logger.info(`🔌 Connection State: ${getConnectionState(conn.connection.readyState)}`);

    // Connection event listeners
    mongoose.connection.on('connected', () => {
      logger.info('🔗 Mongoose connected to MongoDB');
    });

    mongoose.connection.on('error', (err) => {
      logger.error('❌ Mongoose connection error:', err);
    });

    mongoose.connection.on('disconnected', () => {
      logger.warn('⚠️ Mongoose disconnected from MongoDB');
    });

    // Handle application termination
    process.on('SIGINT', async () => {
      await mongoose.connection.close();
      logger.info('🔚 Mongoose connection closed through app termination');
      process.exit(0);
    });

    return conn;
  } catch (error) {
    logger.error('💥 MongoDB connection failed:', error.message);
    
    // Exit process with failure
    setTimeout(() => {
      process.exit(1);
    }, 5000);
  }
};

/**
 * Get human-readable connection state
 * @param {number} state - Mongoose connection state
 * @returns {string} Human-readable state
 */
const getConnectionState = (state) => {
  const states = {
    0: 'Disconnected',
    1: 'Connected',
    2: 'Connecting',
    3: 'Disconnecting',
  };
  return states[state] || 'Unknown';
};

/**
 * Check if database is connected
 * @returns {boolean} Connection status
 */
const isConnected = () => {
  return mongoose.connection.readyState === 1;
};

/**
 * Close database connection
 * @returns {Promise} Close connection promise
 */
const closeConnection = async () => {
  try {
    await mongoose.connection.close();
    logger.info('🔚 MongoDB connection closed successfully');
  } catch (error) {
    logger.error('❌ Error closing MongoDB connection:', error.message);
    throw error;
  }
};

/**
 * Get database statistics
 * @returns {Object} Database statistics
 */
const getDBStats = async () => {
  try {
    if (!isConnected()) {
      throw new Error('Database not connected');
    }

    const admin = mongoose.connection.db.admin();
    const stats = await admin.serverStatus();
    
    return {
      connected: isConnected(),
      host: mongoose.connection.host,
      port: mongoose.connection.port,
      name: mongoose.connection.name,
      version: stats.version,
      uptime: stats.uptime,
      collections: Object.keys(mongoose.connection.collections).length,
      memoryUsage: {
        resident: stats.mem.resident,
        virtual: stats.mem.virtual,
        mapped: stats.mem.mapped || 0,
      },
      connections: {
        current: stats.connections.current,
        available: stats.connections.available,
        totalCreated: stats.connections.totalCreated,
      },
    };
  } catch (error) {
    logger.error('❌ Error getting database stats:', error.message);
    return {
      connected: isConnected(),
      error: error.message,
    };
  }
};

module.exports = {
  connectDB,
  isConnected,
  closeConnection,
  getDBStats,
  getConnectionState,
};