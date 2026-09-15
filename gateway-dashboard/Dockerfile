FROM node:22-alpine

WORKDIR /app

COPY package.json package-lock.json ./
RUN npm ci

COPY . .
RUN npm run build && rm -rf .next/cache

ENV NODE_ENV=production
EXPOSE 5177

CMD ["npm", "start"]
