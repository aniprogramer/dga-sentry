# Frontend Dockerfile — Multi-stage build
# Stage 1: Build the Vite app
# Node 22: vite 8 and vitest 5 in package-lock.json need Node >=20.19 / >=22.12
FROM node:22-slim AS builder

WORKDIR /app

COPY package*.json ./
# --include=dev: the build needs devDependencies (typescript, vite), even if
# NODE_ENV=production or npm's omit=dev setting is present in the environment
# Mirror: registry.npmjs.org resets connections on some networks (same packages)
ARG NPM_REGISTRY=https://registry.yarnpkg.com
RUN --mount=type=cache,target=/root/.npm \
    npm ci --include=dev --registry=$NPM_REGISTRY --fetch-retries=5

COPY . .

# Set the API URL for production (override at deploy time via build arg)
ARG VITE_API_URL=http://localhost:9000
ENV VITE_API_URL=$VITE_API_URL

RUN npm run build

# Stage 2: Serve with nginx
FROM nginx:alpine AS runtime

# Copy built assets
COPY --from=builder /app/dist /usr/share/nginx/html

# Custom nginx config for SPA routing
RUN echo 'server { \
    listen 80; \
    location / { \
        root /usr/share/nginx/html; \
        index index.html; \
        try_files $uri $uri/ /index.html; \
    } \
}' > /etc/nginx/conf.d/default.conf

EXPOSE 80

CMD ["nginx", "-g", "daemon off;"]
