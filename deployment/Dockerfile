FROM node:22-alpine AS build
WORKDIR /src
COPY package.json package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY selfhost/package.json selfhost/package-lock.json ./selfhost/
RUN npm ci --prefix selfhost --no-audit --no-fund
COPY . .
RUN npm --prefix selfhost run build
FROM node:22-alpine AS runtime
ENV NODE_ENV=production
WORKDIR /app
COPY selfhost/package.json selfhost/package-lock.json ./
RUN npm ci --omit=dev --no-audit --no-fund && npm cache clean --force
COPY --from=build /src/selfhost/dist ./dist
COPY selfhost/server ./server
USER node
EXPOSE 3000
CMD ["node", "server/index.mjs"]
