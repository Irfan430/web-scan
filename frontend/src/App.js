/**
 * AI-Powered Cybersecurity Platform - Main App Component
 * Author: IRFAN AHMMED
 */

import React, { useEffect } from 'react';
import { Routes, Route, Navigate } from 'react-router-dom';
import { useDispatch, useSelector } from 'react-redux';
import { Helmet } from 'react-helmet-async';

// Components
import Layout from './components/Layout/Layout';
import LoginPage from './pages/Auth/LoginPage';
import DashboardPage from './pages/Dashboard/DashboardPage';
import ScansPage from './pages/Scans/ScansPage';
import ThreatsPage from './pages/Threats/ThreatsPage';
import ReportsPage from './pages/Reports/ReportsPage';
import SettingsPage from './pages/Settings/SettingsPage';
import ProfilePage from './pages/Profile/ProfilePage';
import LoadingSpinner from './components/UI/LoadingSpinner';
import ProtectedRoute from './components/Auth/ProtectedRoute';

// Services
import { initializeAuth } from './store/slices/authSlice';
import { connectSocket } from './services/socketService';

function App() {
  const dispatch = useDispatch();
  const { isAuthenticated, loading, user } = useSelector((state) => state.auth);

  useEffect(() => {
    // Initialize authentication on app load
    dispatch(initializeAuth());
  }, [dispatch]);

  useEffect(() => {
    // Connect to Socket.IO when authenticated
    if (isAuthenticated && user) {
      connectSocket(user.token);
    }
  }, [isAuthenticated, user]);

  if (loading) {
    return <LoadingSpinner />;
  }

  return (
    <>
      <Helmet>
        <title>🛡️ AI-Powered Cybersecurity Platform</title>
        <meta name="description" content="Comprehensive cybersecurity platform with AI-powered threat detection, vulnerability scanning, and real-time monitoring" />
      </Helmet>
      
      <div className="App min-h-screen bg-slate-900">
        <Routes>
          {/* Public Routes */}
          <Route 
            path="/login" 
            element={
              isAuthenticated ? <Navigate to="/dashboard" replace /> : <LoginPage />
            } 
          />
          
          {/* Protected Routes */}
          <Route path="/" element={<ProtectedRoute />}>
            <Route path="/" element={<Layout />}>
              <Route index element={<Navigate to="/dashboard" replace />} />
              <Route path="dashboard" element={<DashboardPage />} />
              <Route path="scans" element={<ScansPage />} />
              <Route path="threats" element={<ThreatsPage />} />
              <Route path="reports" element={<ReportsPage />} />
              <Route path="settings" element={<SettingsPage />} />
              <Route path="profile" element={<ProfilePage />} />
            </Route>
          </Route>

          {/* Fallback route */}
          <Route path="*" element={<Navigate to="/dashboard" replace />} />
        </Routes>
      </div>
    </>
  );
}

export default App;