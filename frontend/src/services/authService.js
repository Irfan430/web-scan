/**
 * AI-Powered Cybersecurity Platform - Authentication Service
 * Author: IRFAN AHMMED
 */

import apiClient from './apiClient';

class AuthService {
  // Login user
  async login(email, password, mfaCode = null) {
    const payload = { email, password };
    if (mfaCode) {
      payload.mfaCode = mfaCode;
    }
    
    return await apiClient.post('/auth/login', payload);
  }

  // Register new user
  async register(userData) {
    return await apiClient.post('/auth/register', userData);
  }

  // Logout user
  async logout() {
    return await apiClient.post('/auth/logout');
  }

  // Refresh access token
  async refreshToken() {
    return await apiClient.post('/auth/refresh');
  }

  // Verify token validity
  async verifyToken(token) {
    return await apiClient.get('/auth/verify', {
      headers: {
        Authorization: `Bearer ${token}`
      }
    });
  }

  // Request password reset
  async requestPasswordReset(email) {
    return await apiClient.post('/auth/forgot-password', { email });
  }

  // Reset password with token
  async resetPassword(token, newPassword) {
    return await apiClient.post('/auth/reset-password', {
      token,
      password: newPassword
    });
  }

  // Change password (authenticated user)
  async changePassword(currentPassword, newPassword) {
    return await apiClient.post('/auth/change-password', {
      currentPassword,
      newPassword
    });
  }

  // Setup MFA
  async setupMFA() {
    return await apiClient.post('/auth/mfa/setup');
  }

  // Verify MFA setup
  async verifyMFASetup(secret, token) {
    return await apiClient.post('/auth/mfa/verify-setup', {
      secret,
      token
    });
  }

  // Disable MFA
  async disableMFA(password, mfaCode) {
    return await apiClient.post('/auth/mfa/disable', {
      password,
      mfaCode
    });
  }

  // Update user profile
  async updateProfile(profileData) {
    return await apiClient.put('/auth/profile', profileData);
  }

  // Get user profile
  async getProfile() {
    return await apiClient.get('/auth/profile');
  }

  // Update user preferences
  async updatePreferences(preferences) {
    return await apiClient.put('/auth/preferences', preferences);
  }

  // Get security events for user
  async getSecurityEvents(limit = 10) {
    return await apiClient.get(`/auth/security-events?limit=${limit}`);
  }

  // Generate API key
  async generateApiKey(name, permissions = []) {
    return await apiClient.post('/auth/api-keys', { name, permissions });
  }

  // Revoke API key
  async revokeApiKey(keyId) {
    return await apiClient.delete(`/auth/api-keys/${keyId}`);
  }

  // List user's API keys
  async getApiKeys() {
    return await apiClient.get('/auth/api-keys');
  }
}

export default new AuthService();