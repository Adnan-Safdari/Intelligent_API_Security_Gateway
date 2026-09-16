# VITE_* URLs are baked in at build time from the committed .env. The browser
# calls them, so they stay localhost:8082 / localhost:5002.
# Built on the runner's own architecture. The output is static files, identical
# for every platform, and npm ci under arm64 emulation can stall indefinitely --
# it hung the v0.1.5 release for an hour. Only the nginx stage is per-platform.
FROM --platform=$BUILDPLATFORM node:22-alpine AS build

WORKDIR /app

COPY package.json package-lock.json ./
RUN npm ci

COPY . .
RUN npm run build

FROM nginx:1.27-alpine

COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=build /app/dist /usr/share/nginx/html

EXPOSE 80
