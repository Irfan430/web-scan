/**
 * AI-Powered Cybersecurity Platform - Notifications Redux Slice
 * Author: IRFAN AHMMED
 */

import { createSlice } from '@reduxjs/toolkit';

const initialState = {
  notifications: [],
  loading: false,
  error: null,
};

const notificationsSlice = createSlice({
  name: 'notifications',
  initialState,
  reducers: {
    setLoading: (state, action) => {
      state.loading = action.payload;
    },
    setError: (state, action) => {
      state.error = action.payload;
    },
  },
});

export const { setLoading, setError } = notificationsSlice.actions;
export default notificationsSlice.reducer;