/**
 * AI-Powered Cybersecurity Platform - Reports Redux Slice
 * Author: IRFAN AHMMED
 */

import { createSlice } from '@reduxjs/toolkit';

const initialState = {
  reports: [],
  loading: false,
  error: null,
};

const reportsSlice = createSlice({
  name: 'reports',
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

export const { setLoading, setError } = reportsSlice.actions;
export default reportsSlice.reducer;