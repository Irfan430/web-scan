/**
 * Socket.IO Service
 * Handles real-time communication for the cybersecurity platform
 */

const jwt = require('jsonwebtoken');
const User = require('../models/User');
const logger = require('../config/logger');
const { cache } = require('../config/redis');

class SocketService {
  constructor(io) {
    this.io = io;
    this.connectedUsers = new Map();
    this.userSockets = new Map();
    this.organizationRooms = new Map();
  }

  /**
   * Initialize Socket.IO service with authentication and event handlers
   */
  initialize() {
    // Authentication middleware
    this.io.use(async (socket, next) => {
      try {
        const token = socket.handshake.auth.token || socket.handshake.headers.authorization?.replace('Bearer ', '');
        
        if (!token) {
          logger.security('Socket connection failed: No token provided', {
            socketId: socket.id,
            ip: socket.handshake.address
          });
          return next(new Error('Authentication error'));
        }

        // Verify JWT token
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        
        // Get user from database
        const user = await User.findById(decoded.id)
          .select('-password')
          .populate('organization', 'name slug status');

        if (!user || !user.isActive) {
          logger.security('Socket connection failed: Invalid user', {
            socketId: socket.id,
            userId: decoded.id,
            ip: socket.handshake.address
          });
          return next(new Error('Authentication error'));
        }

        // Check organization status
        if (user.organization && user.organization.status !== 'active') {
          logger.security('Socket connection failed: Organization inactive', {
            socketId: socket.id,
            userId: user._id,
            organizationId: user.organization._id,
            ip: socket.handshake.address
          });
          return next(new Error('Organization suspended'));
        }

        // Attach user to socket
        socket.user = user;
        socket.organizationId = user.organization?._id?.toString();
        
        logger.info('Socket authenticated successfully', {
          socketId: socket.id,
          userId: user._id,
          email: user.email,
          organizationId: socket.organizationId
        });

        next();
      } catch (error) {
        logger.security('Socket authentication failed', {
          socketId: socket.id,
          error: error.message,
          ip: socket.handshake.address
        });
        next(new Error('Authentication error'));
      }
    });

    // Connection event
    this.io.on('connection', (socket) => {
      this.handleConnection(socket);
    });

    logger.info('🔌 Socket.IO service initialized');
  }

  /**
   * Handle new socket connection
   * @param {Object} socket - Socket.IO socket instance
   */
  handleConnection(socket) {
    const user = socket.user;
    const userId = user._id.toString();
    const organizationId = socket.organizationId;

    // Track connected user
    this.connectedUsers.set(userId, {
      socketId: socket.id,
      user: user,
      connectedAt: new Date(),
      lastActivity: new Date()
    });

    // Map socket to user
    this.userSockets.set(socket.id, userId);

    // Join organization room
    if (organizationId) {
      socket.join(`org:${organizationId}`);
      
      if (!this.organizationRooms.has(organizationId)) {
        this.organizationRooms.set(organizationId, new Set());
      }
      this.organizationRooms.get(organizationId).add(socket.id);
    }

    // Join user-specific room
    socket.join(`user:${userId}`);

    logger.info('Socket connected', {
      socketId: socket.id,
      userId: userId,
      organizationId: organizationId,
      totalConnections: this.connectedUsers.size
    });

    // Send welcome message
    socket.emit('connected', {
      message: 'Connected to Cybersecurity Platform',
      userId: userId,
      organizationId: organizationId,
      timestamp: new Date().toISOString()
    });

    // Broadcast user online status to organization
    if (organizationId) {
      socket.to(`org:${organizationId}`).emit('user:online', {
        userId: userId,
        userName: user.fullName,
        timestamp: new Date().toISOString()
      });
    }

    // Register event handlers
    this.registerEventHandlers(socket);

    // Handle disconnection
    socket.on('disconnect', (reason) => {
      this.handleDisconnection(socket, reason);
    });
  }

  /**
   * Register event handlers for the socket
   * @param {Object} socket - Socket.IO socket instance
   */
  registerEventHandlers(socket) {
    const userId = socket.user._id.toString();
    const organizationId = socket.organizationId;

    // Scan events
    socket.on('scan:subscribe', (data) => {
      const { scanId } = data;
      socket.join(`scan:${scanId}`);
      logger.debug('User subscribed to scan updates', { userId, scanId });
    });

    socket.on('scan:unsubscribe', (data) => {
      const { scanId } = data;
      socket.leave(`scan:${scanId}`);
      logger.debug('User unsubscribed from scan updates', { userId, scanId });
    });

    // Dashboard events
    socket.on('dashboard:subscribe', () => {
      socket.join(`dashboard:${organizationId}`);
      logger.debug('User subscribed to dashboard updates', { userId, organizationId });
    });

    socket.on('dashboard:unsubscribe', () => {
      socket.leave(`dashboard:${organizationId}`);
      logger.debug('User unsubscribed from dashboard updates', { userId, organizationId });
    });

    // Threat intelligence events
    socket.on('threats:subscribe', () => {
      socket.join(`threats:${organizationId}`);
      logger.debug('User subscribed to threat updates', { userId, organizationId });
    });

    // Chat/collaboration events
    socket.on('chat:join', (data) => {
      const { roomId } = data;
      socket.join(`chat:${roomId}`);
      socket.to(`chat:${roomId}`).emit('chat:user_joined', {
        userId: userId,
        userName: socket.user.fullName,
        timestamp: new Date().toISOString()
      });
    });

    socket.on('chat:message', (data) => {
      const { roomId, message } = data;
      const chatMessage = {
        id: require('crypto').randomUUID(),
        userId: userId,
        userName: socket.user.fullName,
        message: message,
        timestamp: new Date().toISOString()
      };
      
      socket.to(`chat:${roomId}`).emit('chat:message', chatMessage);
      logger.debug('Chat message sent', { userId, roomId, messageId: chatMessage.id });
    });

    // Activity tracking
    socket.on('activity', () => {
      if (this.connectedUsers.has(userId)) {
        this.connectedUsers.get(userId).lastActivity = new Date();
      }
    });

    // Report collaboration
    socket.on('report:collaborate', (data) => {
      const { reportId, action, data: actionData } = data;
      socket.to(`report:${reportId}`).emit('report:collaboration', {
        userId: userId,
        userName: socket.user.fullName,
        action: action,
        data: actionData,
        timestamp: new Date().toISOString()
      });
    });

    // MITRE ATT&CK heatmap updates
    socket.on('mitre:subscribe', () => {
      socket.join(`mitre:${organizationId}`);
      logger.debug('User subscribed to MITRE updates', { userId, organizationId });
    });
  }

  /**
   * Handle socket disconnection
   * @param {Object} socket - Socket.IO socket instance
   * @param {string} reason - Disconnection reason
   */
  handleDisconnection(socket, reason) {
    const userId = this.userSockets.get(socket.id);
    const organizationId = socket.organizationId;

    if (userId) {
      this.connectedUsers.delete(userId);
      this.userSockets.delete(socket.id);

      // Remove from organization room
      if (organizationId && this.organizationRooms.has(organizationId)) {
        this.organizationRooms.get(organizationId).delete(socket.id);
        if (this.organizationRooms.get(organizationId).size === 0) {
          this.organizationRooms.delete(organizationId);
        }
      }

      logger.info('Socket disconnected', {
        socketId: socket.id,
        userId: userId,
        organizationId: organizationId,
        reason: reason,
        totalConnections: this.connectedUsers.size
      });

      // Broadcast user offline status to organization
      if (organizationId) {
        socket.to(`org:${organizationId}`).emit('user:offline', {
          userId: userId,
          timestamp: new Date().toISOString()
        });
      }
    }
  }

  /**
   * Send scan status update to subscribers
   * @param {string} scanId - Scan ID
   * @param {Object} update - Update data
   */
  sendScanUpdate(scanId, update) {
    this.io.to(`scan:${scanId}`).emit('scan:update', {
      scanId: scanId,
      ...update,
      timestamp: new Date().toISOString()
    });

    logger.debug('Scan update sent', { scanId, update });
  }

  /**
   * Send threat alert to organization
   * @param {string} organizationId - Organization ID
   * @param {Object} threat - Threat data
   */
  sendThreatAlert(organizationId, threat) {
    this.io.to(`org:${organizationId}`).emit('threat:alert', {
      ...threat,
      timestamp: new Date().toISOString()
    });

    this.io.to(`threats:${organizationId}`).emit('threat:new', {
      ...threat,
      timestamp: new Date().toISOString()
    });

    logger.info('Threat alert sent', { organizationId, threatId: threat.id });
  }

  /**
   * Send dashboard update to organization
   * @param {string} organizationId - Organization ID
   * @param {Object} data - Dashboard data
   */
  sendDashboardUpdate(organizationId, data) {
    this.io.to(`dashboard:${organizationId}`).emit('dashboard:update', {
      ...data,
      timestamp: new Date().toISOString()
    });

    logger.debug('Dashboard update sent', { organizationId });
  }

  /**
   * Send notification to specific user
   * @param {string} userId - User ID
   * @param {Object} notification - Notification data
   */
  sendUserNotification(userId, notification) {
    this.io.to(`user:${userId}`).emit('notification', {
      ...notification,
      timestamp: new Date().toISOString()
    });

    logger.debug('User notification sent', { userId, type: notification.type });
  }

  /**
   * Send MITRE ATT&CK heatmap update
   * @param {string} organizationId - Organization ID
   * @param {Object} heatmapData - Heatmap data
   */
  sendMitreUpdate(organizationId, heatmapData) {
    this.io.to(`mitre:${organizationId}`).emit('mitre:update', {
      ...heatmapData,
      timestamp: new Date().toISOString()
    });

    logger.debug('MITRE heatmap update sent', { organizationId });
  }

  /**
   * Send system-wide announcement
   * @param {Object} announcement - Announcement data
   */
  sendSystemAnnouncement(announcement) {
    this.io.emit('system:announcement', {
      ...announcement,
      timestamp: new Date().toISOString()
    });

    logger.info('System announcement sent', { type: announcement.type });
  }

  /**
   * Get connected users count
   * @returns {number} Number of connected users
   */
  getConnectedUsersCount() {
    return this.connectedUsers.size;
  }

  /**
   * Get connected users for organization
   * @param {string} organizationId - Organization ID
   * @returns {Array} Connected users
   */
  getOrganizationUsers(organizationId) {
    const users = [];
    this.connectedUsers.forEach((connectionData, userId) => {
      if (connectionData.user.organization?._id?.toString() === organizationId) {
        users.push({
          userId: userId,
          userName: connectionData.user.fullName,
          email: connectionData.user.email,
          connectedAt: connectionData.connectedAt,
          lastActivity: connectionData.lastActivity
        });
      }
    });
    return users;
  }

  /**
   * Check if user is online
   * @param {string} userId - User ID
   * @returns {boolean} Online status
   */
  isUserOnline(userId) {
    return this.connectedUsers.has(userId);
  }

  /**
   * Get socket statistics
   * @returns {Object} Socket statistics
   */
  getStats() {
    return {
      connectedUsers: this.connectedUsers.size,
      totalSockets: this.userSockets.size,
      organizationRooms: this.organizationRooms.size,
      uptime: process.uptime()
    };
  }
}

module.exports = SocketService;