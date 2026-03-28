# Hugging Face Spaces Dockerfile for Cerberus Backend
FROM node:18-alpine

# Set working directory
WORKDIR /app

# Copy package files
COPY package*.json ./

# Install production dependencies only
RUN npm ci --omit=dev --ignore-scripts

# Copy server code
COPY server/ ./server/

# Hugging Face Spaces uses port 7860 by default
ENV PORT=7860
ENV N8N_WEBHOOK_URL=https://n8n.shravanpandala.me/webhook/scan
ENV N8N_TIMEOUT_SECONDS=120

# Expose the port
EXPOSE 7860

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
  CMD node -e "require('http').get('http://localhost:7860/api/health', (r) => {process.exit(r.statusCode === 200 ? 0 : 1)})"

# Start the server
CMD ["node", "server/server.js"]
