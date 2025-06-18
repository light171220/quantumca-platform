# Build stage
FROM node:18-alpine AS builder
WORKDIR /app

# Copy package files
COPY package*.json ./

# Install dependencies
RUN npm ci

# Copy source code
COPY . .

# Copy .env file if it exists
COPY .env* ./

# Set build-time environment variables
ARG REACT_APP_API_URL=http://localhost:8080/api/v1
ARG REACT_APP_HEALTH_URL=http://localhost:8080/health
ARG REACT_APP_OCSP_URL=http://localhost:8081
ARG NODE_ENV=production
ARG GENERATE_SOURCEMAP=false

ENV REACT_APP_API_URL=$REACT_APP_API_URL
ENV REACT_APP_HEALTH_URL=$REACT_APP_HEALTH_URL
ENV REACT_APP_OCSP_URL=$REACT_APP_OCSP_URL
ENV NODE_ENV=$NODE_ENV
ENV GENERATE_SOURCEMAP=$GENERATE_SOURCEMAP

# Build the application
RUN npm run build

# List build output for debugging
RUN ls -la /app/build/

# Production stage
FROM nginx:alpine

# Install curl for healthcheck
RUN apk add --no-cache curl

# Copy custom nginx config
COPY nginx.conf /etc/nginx/conf.d/default.conf

# Copy built application
COPY --from=builder /app/build /usr/share/nginx/html

# Expose port
EXPOSE 3000

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD curl -f http://localhost:3000/health || exit 1

# Start nginx
CMD ["nginx", "-g", "daemon off;"]