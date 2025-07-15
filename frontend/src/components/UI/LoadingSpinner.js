/**
 * AI-Powered Cybersecurity Platform - Loading Spinner Component
 * Author: IRFAN AHMMED
 */

import React from 'react';

const LoadingSpinner = ({ size = 'md', className = '', message = 'Loading...' }) => {
  const sizeClasses = {
    sm: 'w-4 h-4',
    md: 'w-8 h-8',
    lg: 'w-12 h-12',
    xl: 'w-16 h-16',
  };

  return (
    <div className={`flex flex-col items-center justify-center min-h-screen bg-slate-900 ${className}`}>
      <div className="relative">
        {/* Outer ring */}
        <div className={`${sizeClasses[size]} border-4 border-gray-700 rounded-full animate-spin`}>
          <div className="absolute inset-0 border-4 border-transparent border-t-cyan-500 rounded-full animate-spin"></div>
        </div>
        
        {/* Inner ring */}
        <div className={`absolute inset-2 border-2 border-gray-600 rounded-full animate-spin`} style={{ animationDirection: 'reverse' }}>
          <div className="absolute inset-0 border-2 border-transparent border-t-blue-500 rounded-full animate-spin" style={{ animationDirection: 'reverse' }}></div>
        </div>
      </div>
      
      {message && (
        <p className="mt-4 text-gray-300 text-sm font-medium animate-pulse">
          {message}
        </p>
      )}
      
      {/* Additional cyber-style elements */}
      <div className="mt-8 flex space-x-1">
        <div className="w-2 h-2 bg-cyan-500 rounded-full animate-bounce"></div>
        <div className="w-2 h-2 bg-blue-500 rounded-full animate-bounce" style={{ animationDelay: '0.1s' }}></div>
        <div className="w-2 h-2 bg-indigo-500 rounded-full animate-bounce" style={{ animationDelay: '0.2s' }}></div>
      </div>
    </div>
  );
};

export default LoadingSpinner;