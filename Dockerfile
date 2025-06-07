# Base image
FROM node:18-alpine AS base

# Set working directory
WORKDIR /app

# Install dependencies
COPY package.json package-lock.json ./
RUN npm ci

# Copy the rest of the app
COPY . .

# Generate Prisma client
RUN npx prisma generate

# Build TypeScript project
RUN npm run build

# === Runtime container ===
FROM node:18-alpine AS runtime

WORKDIR /app

# Copy node_modules and built code
COPY --from=base /app/node_modules ./node_modules
COPY --from=base /app/dist ./dist
COPY --from=base /app/prisma ./prisma
COPY package.json ./

# Environment variables (can be overridden in docker-compose)
ENV NODE_ENV=production

# Default command (can be overridden in docker-compose for worker)
CMD ["node", "dist/index.js"]
