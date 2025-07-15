/**
 * AI-Powered Cybersecurity Platform - Dashboard Redux Slice
 * Author: IRFAN AHMMED
 */

import { createSlice, createAsyncThunk } from '@reduxjs/toolkit';
import apiClient from '../../services/apiClient';

// Initial state
const initialState = {
  metrics: {
    totalScans: 0,
    activeThreats: 0,
    vulnsFixed: 0,
    riskScore: 0,
  },
  recentScans: [],
  threatAlerts: [],
  systemHealth: {
    cpu: 0,
    memory: 0,
    disk: 0,
    network: 0,
  },
  mitreHeatmap: [],
  loading: false,
  error: null,
  lastUpdated: null,
};

// Async thunks
export const fetchDashboardData = createAsyncThunk(
  'dashboard/fetchData',
  async (_, { rejectWithValue }) => {
    try {
      const response = await apiClient.get('/dashboard/overview');
      return response.data;
    } catch (error) {
      return rejectWithValue(error.response?.data?.message || 'Failed to fetch dashboard data');
    }
  }
);

export const fetchMetrics = createAsyncThunk(
  'dashboard/fetchMetrics',
  async (timeRange = '24h', { rejectWithValue }) => {
    try {
      const response = await apiClient.get(`/dashboard/metrics?timeRange=${timeRange}`);
      return response.data;
    } catch (error) {
      return rejectWithValue(error.response?.data?.message || 'Failed to fetch metrics');
    }
  }
);

export const fetchRecentScans = createAsyncThunk(
  'dashboard/fetchRecentScans',
  async (limit = 10, { rejectWithValue }) => {
    try {
      const response = await apiClient.get(`/dashboard/recent-scans?limit=${limit}`);
      return response.data;
    } catch (error) {
      return rejectWithValue(error.response?.data?.message || 'Failed to fetch recent scans');
    }
  }
);

export const fetchThreatAlerts = createAsyncThunk(
  'dashboard/fetchThreatAlerts',
  async (limit = 5, { rejectWithValue }) => {
    try {
      const response = await apiClient.get(`/dashboard/threat-alerts?limit=${limit}`);
      return response.data;
    } catch (error) {
      return rejectWithValue(error.response?.data?.message || 'Failed to fetch threat alerts');
    }
  }
);

export const fetchSystemHealth = createAsyncThunk(
  'dashboard/fetchSystemHealth',
  async (_, { rejectWithValue }) => {
    try {
      const response = await apiClient.get('/dashboard/system-health');
      return response.data;
    } catch (error) {
      return rejectWithValue(error.response?.data?.message || 'Failed to fetch system health');
    }
  }
);

export const fetchMitreHeatmap = createAsyncThunk(
  'dashboard/fetchMitreHeatmap',
  async (_, { rejectWithValue }) => {
    try {
      const response = await apiClient.get('/dashboard/mitre-heatmap');
      return response.data;
    } catch (error) {
      return rejectWithValue(error.response?.data?.message || 'Failed to fetch MITRE heatmap');
    }
  }
);

// Dashboard slice
const dashboardSlice = createSlice({
  name: 'dashboard',
  initialState,
  reducers: {
    clearError: (state) => {
      state.error = null;
    },
    updateMetric: (state, action) => {
      const { metric, value } = action.payload;
      if (state.metrics.hasOwnProperty(metric)) {
        state.metrics[metric] = value;
      }
    },
    addThreatAlert: (state, action) => {
      state.threatAlerts.unshift(action.payload);
      // Keep only latest 5 alerts
      if (state.threatAlerts.length > 5) {
        state.threatAlerts = state.threatAlerts.slice(0, 5);
      }
    },
    updateSystemHealth: (state, action) => {
      state.systemHealth = { ...state.systemHealth, ...action.payload };
    },
  },
  extraReducers: (builder) => {
    builder
      // Fetch dashboard data
      .addCase(fetchDashboardData.pending, (state) => {
        state.loading = true;
        state.error = null;
      })
      .addCase(fetchDashboardData.fulfilled, (state, action) => {
        state.loading = false;
        state.metrics = action.payload.metrics;
        state.recentScans = action.payload.recentScans;
        state.threatAlerts = action.payload.threatAlerts;
        state.systemHealth = action.payload.systemHealth;
        state.mitreHeatmap = action.payload.mitreHeatmap;
        state.lastUpdated = new Date().toISOString();
      })
      .addCase(fetchDashboardData.rejected, (state, action) => {
        state.loading = false;
        state.error = action.payload;
      })
      
      // Fetch metrics
      .addCase(fetchMetrics.fulfilled, (state, action) => {
        state.metrics = action.payload;
      })
      
      // Fetch recent scans
      .addCase(fetchRecentScans.fulfilled, (state, action) => {
        state.recentScans = action.payload;
      })
      
      // Fetch threat alerts
      .addCase(fetchThreatAlerts.fulfilled, (state, action) => {
        state.threatAlerts = action.payload;
      })
      
      // Fetch system health
      .addCase(fetchSystemHealth.fulfilled, (state, action) => {
        state.systemHealth = action.payload;
      })
      
      // Fetch MITRE heatmap
      .addCase(fetchMitreHeatmap.fulfilled, (state, action) => {
        state.mitreHeatmap = action.payload;
      });
  },
});

export const {
  clearError,
  updateMetric,
  addThreatAlert,
  updateSystemHealth,
} = dashboardSlice.actions;

export default dashboardSlice.reducer;