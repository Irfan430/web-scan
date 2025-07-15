# AI-Powered Cybersecurity Platform - Backend Dockerfile
# Author: IRFAN AHMMED
# Multi-stage build for production optimization

# Build stage
FROM node:18-alpine AS builder

# Set working directory
WORKDIR /app

# Install build dependencies
RUN apk add --no-cache \
    python3 \
    make \
    g++ \
    git

# Copy package files
COPY package*.json ./

# Install dependencies
RUN npm ci --only=production && npm cache clean --force

# Copy source code
COPY . .

# Production stage
FROM node:18-alpine AS production

# Create non-root user for security
RUN addgroup -g 1001 -S nodejs && \
    adduser -S nodeuser -u 1001

# Install security updates and required tools
RUN apk update && \
    apk upgrade && \
    apk add --no-cache \
    dumb-init \
    tini \
    curl \
    && rm -rf /var/cache/apk/*

# Set working directory
WORKDIR /app

# Copy built application from builder stage
COPY --from=builder --chown=nodeuser:nodejs /app/node_modules ./node_modules
COPY --from=builder --chown=nodeuser:nodejs /app/src ./src
COPY --from=builder --chown=nodeuser:nodejs /app/package*.json ./

# Create necessary directories
RUN mkdir -p logs uploads temp && \
    chown -R nodeuser:nodejs /app

# Security: Remove unnecessary packages and create restricted user
RUN apk del git make g++ python3

# Switch to non-root user
USER nodeuser

# Expose port
EXPOSE 5000

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:5000/health || exit 1

# Set environment variables
ENV NODE_ENV=production
ENV PORT=5000

# Use tini as init system for proper signal handling
ENTRYPOINT ["tini", "--"]

# Start the application
CMD ["node", "src/app.js"]

# Metadata
LABEL maintainer="IRFAN AHMMED"
LABEL description="AI-Powered Cybersecurity Platform Backend"
LABEL version="1.0.0"