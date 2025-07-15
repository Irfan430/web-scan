/**
 * AI-Powered Cybersecurity Platform - Socket.IO Service
 * Author: IRFAN AHMMED
 */

import { io } from 'socket.io-client';
import { store } from '../store/store';
import { addNotification } from '../store/slices/uiSlice';
import { addThreatAlert, updateSystemHealth } from '../store/slices/dashboardSlice';
import toast from 'react-hot-toast';

class SocketService {
  constructor() {
    this.socket = null;
    this.isConnected = false;
    this.reconnectAttempts = 0;
    this.maxReconnectAttempts = 5;
  }

  connect(token) {
    if (this.socket && this.isConnected) {
      return;
    }

    const socketUrl = process.env.REACT_APP_WS_URL || 'http://localhost:5000';
    
    this.socket = io(socketUrl, {
      auth: {
        token: token
      },
      transports: ['websocket', 'polling'],
      timeout: 20000,
      retries: 3,
    });

    this.setupEventListeners();
  }

  setupEventListeners() {
    if (!this.socket) return;

    // Connection events
    this.socket.on('connect', () => {
      this.isConnected = true;
      this.reconnectAttempts = 0;
      console.log('✅ Socket connected:', this.socket.id);
      toast.success('Real-time connection established');
    });

    this.socket.on('disconnect', (reason) => {
      this.isConnected = false;
      console.log('❌ Socket disconnected:', reason);
      
      if (reason === 'io server disconnect') {
        // Server disconnected, need manual reconnection
        this.reconnect();
      }
    });

    this.socket.on('connect_error', (error) => {
      console.error('Socket connection error:', error);
      this.handleConnectionError();
    });

    // Custom events
    this.setupCustomEventListeners();
  }

  setupCustomEventListeners() {
    // Security events
    this.socket.on('threat_detected', (data) => {
      console.log('🚨 Threat detected:', data);
      
      store.dispatch(addThreatAlert(data));
      store.dispatch(addNotification({
        type: 'error',
        title: 'Threat Detected',
        message: `${data.threatType} detected on ${data.target}`,
        severity: data.severity,
      }));

      // Show toast based on severity
      if (data.severity === 'critical') {
        toast.error(`Critical threat detected: ${data.threatType}`);
      } else if (data.severity === 'high') {
        toast.error(`High severity threat: ${data.threatType}`);
      }
    });

    this.socket.on('scan_completed', (data) => {
      console.log('✅ Scan completed:', data);
      
      store.dispatch(addNotification({
        type: 'success',
        title: 'Scan Completed',
        message: `${data.scanType} scan finished with ${data.findings} findings`,
      }));

      toast.success(`Scan completed: ${data.findings} findings`);
    });

    this.socket.on('scan_failed', (data) => {
      console.log('❌ Scan failed:', data);
      
      store.dispatch(addNotification({
        type: 'error',
        title: 'Scan Failed',
        message: `${data.scanType} scan failed: ${data.error}`,
      }));

      toast.error(`Scan failed: ${data.error}`);
    });

    this.socket.on('system_health_update', (data) => {
      store.dispatch(updateSystemHealth(data));
    });

    this.socket.on('user_activity', (data) => {
      console.log('👤 User activity:', data);
      
      if (data.type === 'login_suspicious') {
        store.dispatch(addNotification({
          type: 'warning',
          title: 'Suspicious Login Detected',
          message: `Login from ${data.location} at ${data.timestamp}`,
        }));
      }
    });

    this.socket.on('vulnerability_found', (data) => {
      console.log('🔍 Vulnerability found:', data);
      
      store.dispatch(addNotification({
        type: 'warning',
        title: 'Vulnerability Found',
        message: `${data.severity} vulnerability: ${data.cve}`,
      }));
    });

    this.socket.on('compliance_alert', (data) => {
      console.log('📋 Compliance alert:', data);
      
      store.dispatch(addNotification({
        type: 'info',
        title: 'Compliance Alert',
        message: `${data.framework}: ${data.message}`,
      }));
    });

    // Real-time dashboard updates
    this.socket.on('metrics_update', (data) => {
      // Update metrics in dashboard slice
      Object.entries(data).forEach(([metric, value]) => {
        store.dispatch(updateMetric({ metric, value }));
      });
    });

    // Chat/collaboration events
    this.socket.on('team_message', (data) => {
      store.dispatch(addNotification({
        type: 'info',
        title: 'Team Message',
        message: `${data.from}: ${data.message}`,
      }));
    });

    // Error events
    this.socket.on('error', (error) => {
      console.error('Socket error:', error);
      toast.error('Real-time connection error');
    });
  }

  handleConnectionError() {
    if (this.reconnectAttempts < this.maxReconnectAttempts) {
      this.reconnectAttempts++;
      setTimeout(() => {
        console.log(`Attempting to reconnect... (${this.reconnectAttempts}/${this.maxReconnectAttempts})`);
        this.socket?.connect();
      }, Math.pow(2, this.reconnectAttempts) * 1000); // Exponential backoff
    } else {
      toast.error('Unable to establish real-time connection');
    }
  }

  reconnect() {
    if (this.reconnectAttempts < this.maxReconnectAttempts) {
      this.handleConnectionError();
    }
  }

  // Emit events
  joinRoom(room) {
    if (this.socket && this.isConnected) {
      this.socket.emit('join_room', room);
    }
  }

  leaveRoom(room) {
    if (this.socket && this.isConnected) {
      this.socket.emit('leave_room', room);
    }
  }

  startScan(scanConfig) {
    if (this.socket && this.isConnected) {
      this.socket.emit('start_scan', scanConfig);
    }
  }

  stopScan(scanId) {
    if (this.socket && this.isConnected) {
      this.socket.emit('stop_scan', { scanId });
    }
  }

  sendTeamMessage(message) {
    if (this.socket && this.isConnected) {
      this.socket.emit('team_message', message);
    }
  }

  // Disconnect
  disconnect() {
    if (this.socket) {
      this.socket.disconnect();
      this.socket = null;
      this.isConnected = false;
      this.reconnectAttempts = 0;
    }
  }

  // Get connection status
  getConnectionStatus() {
    return {
      connected: this.isConnected,
      socketId: this.socket?.id,
      reconnectAttempts: this.reconnectAttempts,
    };
  }
}

// Create singleton instance
const socketService = new SocketService();

// Export methods for easy access
export const connectSocket = (token) => socketService.connect(token);
export const disconnectSocket = () => socketService.disconnect();
export const joinRoom = (room) => socketService.joinRoom(room);
export const leaveRoom = (room) => socketService.leaveRoom(room);
export const startScan = (config) => socketService.startScan(config);
export const stopScan = (scanId) => socketService.stopScan(scanId);
export const sendTeamMessage = (message) => socketService.sendTeamMessage(message);
export const getConnectionStatus = () => socketService.getConnectionStatus();

export default socketService;