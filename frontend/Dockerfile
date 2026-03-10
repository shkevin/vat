FROM node:20-alpine

WORKDIR /app

# Copy package files
COPY package.json package-lock.json* ./
RUN npm ci

# Copy source
COPY . .

# Dev server (for docker-compose dev)
CMD ["npm", "run", "dev"]
