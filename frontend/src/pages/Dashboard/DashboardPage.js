/**
 * AI-Powered Cybersecurity Platform - Dashboard Page
 * Author: IRFAN AHMMED
 */

import React, { useEffect } from 'react';
import { useDispatch, useSelector } from 'react-redux';
import { motion } from 'framer-motion';
import { ShieldCheckIcon, ExclamationTriangleIcon, BugAntIcon, ChartBarIcon } from '@heroicons/react/24/outline';
import { fetchDashboardData } from '../../store/slices/dashboardSlice';

const DashboardPage = () => {
  const dispatch = useDispatch();
  const { metrics, loading, error } = useSelector((state) => state.dashboard);

  useEffect(() => {
    dispatch(fetchDashboardData());
  }, [dispatch]);

  const metricCards = [
    {
      title: 'Total Scans',
      value: metrics.totalScans || 247,
      icon: ChartBarIcon,
      color: 'text-cyan-400',
      bgColor: 'bg-cyan-500/20',
      borderColor: 'border-cyan-500/30',
    },
    {
      title: 'Active Threats',
      value: metrics.activeThreats || 12,
      icon: ExclamationTriangleIcon,
      color: 'text-red-400',
      bgColor: 'bg-red-500/20',
      borderColor: 'border-red-500/30',
    },
    {
      title: 'Vulnerabilities Fixed',
      value: metrics.vulnsFixed || 89,
      icon: BugAntIcon,
      color: 'text-green-400',
      bgColor: 'bg-green-500/20',
      borderColor: 'border-green-500/30',
    },
    {
      title: 'Risk Score',
      value: metrics.riskScore || '75%',
      icon: ShieldCheckIcon,
      color: 'text-amber-400',
      bgColor: 'bg-amber-500/20',
      borderColor: 'border-amber-500/30',
    },
  ];

  if (loading) {
    return (
      <div className="flex items-center justify-center min-h-96">
        <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-cyan-500"></div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <h1 className="text-3xl font-bold text-white">Security Dashboard</h1>
        <div className="text-sm text-gray-400">
          Last updated: {new Date().toLocaleTimeString()}
        </div>
      </div>

      {/* Metrics Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        {metricCards.map((metric, index) => (
          <motion.div
            key={metric.title}
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.5, delay: index * 0.1 }}
            className={`${metric.bgColor} ${metric.borderColor} border rounded-lg p-6 hover:border-opacity-60 transition-all duration-300`}
          >
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm font-medium text-gray-300">{metric.title}</p>
                <p className={`text-2xl font-bold ${metric.color}`}>{metric.value}</p>
              </div>
              <metric.icon className={`h-8 w-8 ${metric.color}`} />
            </div>
          </motion.div>
        ))}
      </div>

      {/* Welcome Message */}
      <motion.div
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        transition={{ duration: 0.8, delay: 0.5 }}
        className="glass-morphism rounded-lg p-8 text-center"
      >
        <h2 className="text-2xl font-bold text-white mb-4">Welcome to Your Security Command Center</h2>
        <p className="text-gray-300 mb-6">
          Your AI-powered cybersecurity platform is ready to protect your infrastructure. 
          Monitor threats, run scans, and maintain security posture all from this centralized dashboard.
        </p>
        <div className="flex justify-center space-x-4">
          <button className="cyber-gradient px-6 py-3 rounded-lg text-white font-medium hover:opacity-90 transition-opacity">
            Start New Scan
          </button>
          <button className="border border-gray-600 px-6 py-3 rounded-lg text-gray-300 hover:bg-gray-800 transition-colors">
            View Reports
          </button>
        </div>
      </motion.div>

      {/* Status Indicators */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <motion.div
          initial={{ opacity: 0, x: -20 }}
          animate={{ opacity: 1, x: 0 }}
          transition={{ duration: 0.6, delay: 0.7 }}
          className="glass-morphism rounded-lg p-6"
        >
          <h3 className="text-lg font-semibold text-white mb-4">System Health</h3>
          <div className="space-y-3">
            <div className="flex justify-between items-center">
              <span className="text-gray-300">Network Security</span>
              <span className="text-green-400">Online</span>
            </div>
            <div className="flex justify-between items-center">
              <span className="text-gray-300">Threat Detection</span>
              <span className="text-green-400">Active</span>
            </div>
            <div className="flex justify-between items-center">
              <span className="text-gray-300">ML Risk Analysis</span>
              <span className="text-cyan-400">Processing</span>
            </div>
          </div>
        </motion.div>

        <motion.div
          initial={{ opacity: 0, x: 20 }}
          animate={{ opacity: 1, x: 0 }}
          transition={{ duration: 0.6, delay: 0.8 }}
          className="glass-morphism rounded-lg p-6"
        >
          <h3 className="text-lg font-semibold text-white mb-4">Recent Activity</h3>
          <div className="space-y-3">
            <div className="flex items-center text-sm">
              <div className="w-2 h-2 bg-green-400 rounded-full mr-3"></div>
              <span className="text-gray-300">Vulnerability scan completed - 0 critical issues</span>
            </div>
            <div className="flex items-center text-sm">
              <div className="w-2 h-2 bg-yellow-400 rounded-full mr-3"></div>
              <span className="text-gray-300">New threat intelligence feed updated</span>
            </div>
            <div className="flex items-center text-sm">
              <div className="w-2 h-2 bg-blue-400 rounded-full mr-3"></div>
              <span className="text-gray-300">MITRE ATT&CK mapping refreshed</span>
            </div>
          </div>
        </motion.div>
      </div>
    </div>
  );
};

export default DashboardPage;