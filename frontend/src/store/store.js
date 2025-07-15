/**
 * AI-Powered Cybersecurity Platform - Redux Store Configuration
 * Author: IRFAN AHMMED
 */

import { configureStore } from '@reduxjs/toolkit';

// Import reducers
import authReducer from './slices/authSlice';
import dashboardReducer from './slices/dashboardSlice';
import scansReducer from './slices/scansSlice';
import threatsReducer from './slices/threatsSlice';
import reportsReducer from './slices/reportsSlice';
import settingsReducer from './slices/settingsSlice';
import notificationsReducer from './slices/notificationsSlice';
import uiReducer from './slices/uiSlice';

export const store = configureStore({
  reducer: {
    auth: authReducer,
    dashboard: dashboardReducer,
    scans: scansReducer,
    threats: threatsReducer,
    reports: reportsReducer,
    settings: settingsReducer,
    notifications: notificationsReducer,
    ui: uiReducer,
  },
  middleware: (getDefaultMiddleware) =>
    getDefaultMiddleware({
      serializableCheck: {
        ignoredActions: ['persist/PERSIST', 'persist/REHYDRATE'],
      },
    }),
  devTools: process.env.NODE_ENV !== 'production',
});

export type RootState = ReturnType<typeof store.getState>;
export type AppDispatch = typeof store.dispatch;