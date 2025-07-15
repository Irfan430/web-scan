/**
 * AI-Powered Cybersecurity Platform - Scans Redux Slice
 * Author: IRFAN AHMMED
 */

import { createSlice } from '@reduxjs/toolkit';

const initialState = {
  scans: [],
  loading: false,
  error: null,
};

const scansSlice = createSlice({
  name: 'scans',
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

export const { setLoading, setError } = scansSlice.actions;
export default scansSlice.reducer;