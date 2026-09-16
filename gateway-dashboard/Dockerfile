# Built on the builder's own architecture, never the target's. npm ci and next
# build under QEMU are what made the arm64 half of this image take over half an
# hour against twenty seconds native, so nothing is executed for the target
# platform here -- only finished output is copied into it. Every dependency is
# pure JavaScript, so none of that output is architecture-specific.
FROM --platform=$BUILDPLATFORM node:22-alpine AS builder

WORKDIR /app

COPY package.json package-lock.json ./
RUN npm ci

COPY . .
RUN npm run build

FROM node:22-alpine

WORKDIR /app

ENV NODE_ENV=production
# standalone's server.js takes these from the environment; the -H and -p flags
# that `next start` used are not read.
ENV PORT=5177
ENV HOSTNAME=0.0.0.0

# next.config.mjs sets output: "standalone", which traces the runtime
# dependencies into .next/standalone but deliberately leaves the static assets
# out of it, so they are copied separately.
COPY --from=builder /app/.next/standalone ./
COPY --from=builder /app/.next/static ./.next/static

EXPOSE 5177

CMD ["node", "server.js"]
