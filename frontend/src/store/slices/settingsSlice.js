/**
 * AI-Powered Cybersecurity Platform - Settings Redux Slice
 * Author: IRFAN AHMMED
 */

import { createSlice } from '@reduxjs/toolkit';

const initialState = {
  settings: {},
  loading: false,
  error: null,
};

const settingsSlice = createSlice({
  name: 'settings',
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

export const { setLoading, setError } = settingsSlice.actions;
export default settingsSlice.reducer;