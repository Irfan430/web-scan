/**
 * AI-Powered Cybersecurity Platform - UI Redux Slice
 * Author: IRFAN AHMMED
 */

import { createSlice } from '@reduxjs/toolkit';

// Initial state
const initialState = {
  sidebarOpen: false,
  theme: 'dark',
  notifications: [],
  modals: {
    scanModal: false,
    threatModal: false,
    settingsModal: false,
  },
  loading: {
    global: false,
    scan: false,
    threat: false,
    report: false,
  },
  filters: {
    dateRange: '7d',
    threatLevel: 'all',
    scanType: 'all',
  },
  searchQuery: '',
  selectedItems: [],
};

// UI slice
const uiSlice = createSlice({
  name: 'ui',
  initialState,
  reducers: {
    // Sidebar actions
    toggleSidebar: (state) => {
      state.sidebarOpen = !state.sidebarOpen;
    },
    setSidebarOpen: (state, action) => {
      state.sidebarOpen = action.payload;
    },
    
    // Theme actions
    setTheme: (state, action) => {
      state.theme = action.payload;
      localStorage.setItem('theme', action.payload);
    },
    
    // Notification actions
    addNotification: (state, action) => {
      const notification = {
        id: Date.now(),
        timestamp: new Date().toISOString(),
        ...action.payload,
      };
      state.notifications.unshift(notification);
      
      // Keep only latest 50 notifications
      if (state.notifications.length > 50) {
        state.notifications = state.notifications.slice(0, 50);
      }
    },
    removeNotification: (state, action) => {
      state.notifications = state.notifications.filter(
        notification => notification.id !== action.payload
      );
    },
    clearAllNotifications: (state) => {
      state.notifications = [];
    },
    markNotificationAsRead: (state, action) => {
      const notification = state.notifications.find(n => n.id === action.payload);
      if (notification) {
        notification.read = true;
      }
    },
    
    // Modal actions
    openModal: (state, action) => {
      const { modalName } = action.payload;
      if (state.modals.hasOwnProperty(modalName)) {
        state.modals[modalName] = true;
      }
    },
    closeModal: (state, action) => {
      const { modalName } = action.payload;
      if (state.modals.hasOwnProperty(modalName)) {
        state.modals[modalName] = false;
      }
    },
    closeAllModals: (state) => {
      Object.keys(state.modals).forEach(modalName => {
        state.modals[modalName] = false;
      });
    },
    
    // Loading actions
    setLoading: (state, action) => {
      const { key, value } = action.payload;
      if (state.loading.hasOwnProperty(key)) {
        state.loading[key] = value;
      }
    },
    setGlobalLoading: (state, action) => {
      state.loading.global = action.payload;
    },
    
    // Filter actions
    setFilter: (state, action) => {
      const { filterName, value } = action.payload;
      if (state.filters.hasOwnProperty(filterName)) {
        state.filters[filterName] = value;
      }
    },
    resetFilters: (state) => {
      state.filters = {
        dateRange: '7d',
        threatLevel: 'all',
        scanType: 'all',
      };
    },
    
    // Search actions
    setSearchQuery: (state, action) => {
      state.searchQuery = action.payload;
    },
    clearSearchQuery: (state) => {
      state.searchQuery = '';
    },
    
    // Selection actions
    setSelectedItems: (state, action) => {
      state.selectedItems = action.payload;
    },
    addSelectedItem: (state, action) => {
      if (!state.selectedItems.includes(action.payload)) {
        state.selectedItems.push(action.payload);
      }
    },
    removeSelectedItem: (state, action) => {
      state.selectedItems = state.selectedItems.filter(
        item => item !== action.payload
      );
    },
    clearSelectedItems: (state) => {
      state.selectedItems = [];
    },
    toggleItemSelection: (state, action) => {
      const item = action.payload;
      const index = state.selectedItems.indexOf(item);
      
      if (index === -1) {
        state.selectedItems.push(item);
      } else {
        state.selectedItems.splice(index, 1);
      }
    },
  },
});

export const {
  toggleSidebar,
  setSidebarOpen,
  setTheme,
  addNotification,
  removeNotification,
  clearAllNotifications,
  markNotificationAsRead,
  openModal,
  closeModal,
  closeAllModals,
  setLoading,
  setGlobalLoading,
  setFilter,
  resetFilters,
  setSearchQuery,
  clearSearchQuery,
  setSelectedItems,
  addSelectedItem,
  removeSelectedItem,
  clearSelectedItems,
  toggleItemSelection,
} = uiSlice.actions;

export default uiSlice.reducer;