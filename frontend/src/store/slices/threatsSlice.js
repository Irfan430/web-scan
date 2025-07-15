/**
 * AI-Powered Cybersecurity Platform - Threats Redux Slice
 * Author: IRFAN AHMMED
 */

import { createSlice } from '@reduxjs/toolkit';

const initialState = {
  threats: [],
  loading: false,
  error: null,
};

const threatsSlice = createSlice({
  name: 'threats',
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

export const { setLoading, setError } = threatsSlice.actions;
export default threatsSlice.reducer;