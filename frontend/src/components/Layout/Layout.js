/**
 * AI-Powered Cybersecurity Platform - Main Layout Component
 * Author: IRFAN AHMMED
 */

import React from 'react';
import { Outlet } from 'react-router-dom';
import { motion } from 'framer-motion';

const Layout = () => {
  return (
    <div className="min-h-screen bg-slate-900 flex">
      {/* Sidebar Placeholder */}
      <aside className="w-64 bg-slate-800 border-r border-slate-700 p-4">
        <div className="text-white">
          <h2 className="text-lg font-bold mb-4">🛡️ CyberSec Platform</h2>
          <nav className="space-y-2">
            <a href="/dashboard" className="block p-2 rounded hover:bg-slate-700 text-cyan-400">Dashboard</a>
            <a href="/scans" className="block p-2 rounded hover:bg-slate-700">Scans</a>
            <a href="/threats" className="block p-2 rounded hover:bg-slate-700">Threats</a>
            <a href="/reports" className="block p-2 rounded hover:bg-slate-700">Reports</a>
            <a href="/settings" className="block p-2 rounded hover:bg-slate-700">Settings</a>
          </nav>
        </div>
      </aside>

      {/* Main Content */}
      <main className="flex-1 overflow-auto">
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.5 }}
          className="p-6"
        >
          <Outlet />
        </motion.div>
      </main>
    </div>
  );
};

export default Layout;