# Official Node.js 20 Alpine Base Image
FROM node:20-alpine

# Set container working directory
WORKDIR /app

# Copy dependency manifests
COPY package*.json ./

# Install production dependencies cleanly
RUN npm ci --only=production

# Copy application source code
COPY . .

# Set environment variables
ENV PORT=8080
ENV NODE_ENV=production

# Expose HTTP port
EXPOSE 8080

# Start Void Proxy server
CMD ["node", "server.js"]
