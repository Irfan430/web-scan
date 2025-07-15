/**
 * Redis Configuration
 * Handles Redis connection for caching and queue management
 */

const { createClient } = require('redis');
const logger = require('./logger');

let redisClient = null;

/**
 * Connect to Redis
 * @returns {Promise} Redis client
 */
const connectRedis = async () => {
  try {
    // Create Redis client
    redisClient = createClient({
      url: process.env.REDIS_URL || 'redis://localhost:6379',
      retry_strategy: (options) => {
        if (options.error && options.error.code === 'ECONNREFUSED') {
          logger.error('❌ Redis server connection refused');
          return new Error('Redis server connection refused');
        }
        if (options.total_retry_time > 1000 * 60 * 60) {
          logger.error('❌ Redis retry time exhausted');
          return new Error('Redis retry time exhausted');
        }
        if (options.attempt > 10) {
          logger.error('❌ Redis max retry attempts exceeded');
          return undefined;
        }
        // Reconnect after
        return Math.min(options.attempt * 100, 3000);
      },
      socket: {
        connectTimeout: 60000,
        commandTimeout: 5000,
        lazyConnect: true,
      },
    });

    // Event listeners
    redisClient.on('error', (err) => {
      logger.error('❌ Redis Client Error:', err);
    });

    redisClient.on('connect', () => {
      logger.info('🔗 Redis client connected');
    });

    redisClient.on('ready', () => {
      logger.info('✅ Redis client ready to receive commands');
    });

    redisClient.on('end', () => {
      logger.warn('⚠️ Redis client connection closed');
    });

    redisClient.on('reconnecting', () => {
      logger.info('🔄 Redis client reconnecting...');
    });

    // Connect to Redis
    await redisClient.connect();

    // Test connection
    await redisClient.ping();
    logger.info('🏓 Redis connection successful - PONG received');

    // Set default expiration time (24 hours)
    const defaultTTL = 24 * 60 * 60; // 24 hours in seconds

    return redisClient;
  } catch (error) {
    logger.error('💥 Redis connection failed:', error.message);
    throw error;
  }
};

/**
 * Get Redis client instance
 * @returns {Object} Redis client
 */
const getRedisClient = () => {
  if (!redisClient) {
    throw new Error('Redis client not initialized. Call connectRedis() first.');
  }
  return redisClient;
};

/**
 * Check if Redis is connected
 * @returns {boolean} Connection status
 */
const isRedisConnected = () => {
  return redisClient && redisClient.isOpen;
};

/**
 * Close Redis connection
 * @returns {Promise} Close connection promise
 */
const closeRedisConnection = async () => {
  try {
    if (redisClient && redisClient.isOpen) {
      await redisClient.quit();
      logger.info('🔚 Redis connection closed successfully');
    }
  } catch (error) {
    logger.error('❌ Error closing Redis connection:', error.message);
    throw error;
  }
};

/**
 * Cache helper functions
 */
const cache = {
  /**
   * Set cache with TTL
   * @param {string} key - Cache key
   * @param {*} value - Value to cache
   * @param {number} ttl - Time to live in seconds (default: 3600)
   */
  set: async (key, value, ttl = 3600) => {
    try {
      const client = getRedisClient();
      const serializedValue = JSON.stringify(value);
      await client.setEx(key, ttl, serializedValue);
      logger.debug(`📦 Cached: ${key} (TTL: ${ttl}s)`);
    } catch (error) {
      logger.error('❌ Cache set error:', error);
      throw error;
    }
  },

  /**
   * Get cached value
   * @param {string} key - Cache key
   * @returns {*} Cached value or null
   */
  get: async (key) => {
    try {
      const client = getRedisClient();
      const cachedValue = await client.get(key);
      if (cachedValue) {
        logger.debug(`📥 Cache hit: ${key}`);
        return JSON.parse(cachedValue);
      }
      logger.debug(`📭 Cache miss: ${key}`);
      return null;
    } catch (error) {
      logger.error('❌ Cache get error:', error);
      return null;
    }
  },

  /**
   * Delete cached value
   * @param {string} key - Cache key
   */
  del: async (key) => {
    try {
      const client = getRedisClient();
      await client.del(key);
      logger.debug(`🗑️ Cache deleted: ${key}`);
    } catch (error) {
      logger.error('❌ Cache delete error:', error);
      throw error;
    }
  },

  /**
   * Check if key exists in cache
   * @param {string} key - Cache key
   * @returns {boolean} Key exists
   */
  exists: async (key) => {
    try {
      const client = getRedisClient();
      const exists = await client.exists(key);
      return exists === 1;
    } catch (error) {
      logger.error('❌ Cache exists error:', error);
      return false;
    }
  },

  /**
   * Get cache TTL
   * @param {string} key - Cache key
   * @returns {number} TTL in seconds
   */
  ttl: async (key) => {
    try {
      const client = getRedisClient();
      return await client.ttl(key);
    } catch (error) {
      logger.error('❌ Cache TTL error:', error);
      return -1;
    }
  },

  /**
   * Clear all cache
   */
  flush: async () => {
    try {
      const client = getRedisClient();
      await client.flushAll();
      logger.info('🧹 All cache cleared');
    } catch (error) {
      logger.error('❌ Cache flush error:', error);
      throw error;
    }
  },
};

/**
 * Session management functions
 */
const session = {
  /**
   * Set user session
   * @param {string} userId - User ID
   * @param {Object} sessionData - Session data
   * @param {number} ttl - Session TTL in seconds
   */
  set: async (userId, sessionData, ttl = 24 * 60 * 60) => {
    const key = `session:${userId}`;
    await cache.set(key, sessionData, ttl);
  },

  /**
   * Get user session
   * @param {string} userId - User ID
   * @returns {Object} Session data
   */
  get: async (userId) => {
    const key = `session:${userId}`;
    return await cache.get(key);
  },

  /**
   * Delete user session
   * @param {string} userId - User ID
   */
  del: async (userId) => {
    const key = `session:${userId}`;
    await cache.del(key);
  },
};

/**
 * Get Redis statistics
 * @returns {Object} Redis statistics
 */
const getRedisStats = async () => {
  try {
    if (!isRedisConnected()) {
      throw new Error('Redis not connected');
    }

    const client = getRedisClient();
    const info = await client.info();
    const stats = {};

    // Parse info string
    info.split('\r\n').forEach((line) => {
      if (line && !line.startsWith('#')) {
        const [key, value] = line.split(':');
        if (key && value) {
          stats[key] = value;
        }
      }
    });

    return {
      connected: isRedisConnected(),
      version: stats.redis_version,
      mode: stats.redis_mode,
      uptime: parseInt(stats.uptime_in_seconds),
      connectedClients: parseInt(stats.connected_clients),
      usedMemory: stats.used_memory_human,
      totalCommandsProcessed: parseInt(stats.total_commands_processed),
      keyspaceHits: parseInt(stats.keyspace_hits),
      keyspaceMisses: parseInt(stats.keyspace_misses),
      hitRate: stats.keyspace_hits && stats.keyspace_misses 
        ? ((parseInt(stats.keyspace_hits) / (parseInt(stats.keyspace_hits) + parseInt(stats.keyspace_misses))) * 100).toFixed(2) + '%'
        : 'N/A',
    };
  } catch (error) {
    logger.error('❌ Error getting Redis stats:', error.message);
    return {
      connected: isRedisConnected(),
      error: error.message,
    };
  }
};

module.exports = {
  connectRedis,
  getRedisClient,
  isRedisConnected,
  closeRedisConnection,
  cache,
  session,
  getRedisStats,
};