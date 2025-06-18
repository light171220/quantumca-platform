# Build stage
FROM node:18-alpine AS builder

WORKDIR /app

# Copy package files
COPY package*.json ./

# Install dependencies
RUN npm ci --only=production

# Copy source code
COPY . .

# Build the application
RUN npm run build

# Production stage
FROM nginx:alpine

# Install curl for healthcheck
RUN apk add --no-cache curl

# Copy custom nginx config
COPY nginx.conf /etc/nginx/conf.d/default.conf

# Copy built application
COPY --from=builder /app/build /usr/share/nginx/html

# Create non-root user
RUN addgroup -g 1001 -S quantumca && \
    adduser -S quantumca -u 1001 -G quantumca

# Change ownership of nginx files
RUN chown -R quantumca:quantumca /var/cache/nginx && \
    chown -R quantumca:quantumca /var/log/nginx && \
    chown -R quantumca:quantumca /etc/nginx/conf.d && \
    touch /var/run/nginx.pid && \
    chown -R quantumca:quantumca /var/run/nginx.pid

# Switch to non-root user
USER quantumca

# Expose port
EXPOSE 3000

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:3000/health || exit 1

# Start nginx
CMD ["nginx", "-g", "daemon off;"]