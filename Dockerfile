# Build and run both Node services from one reproducible workspace image.
FROM node:22-bookworm-slim AS build
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends python3 make g++ && rm -rf /var/lib/apt/lists/*
COPY package.json ./
COPY packages/entec-core/package.json packages/entec-core/package.json
COPY packages/tagengine/package.json packages/tagengine/package.json
RUN npm install
COPY packages ./packages
COPY apps ./apps
COPY docs ./docs
RUN npm run build

FROM node:22-bookworm-slim AS runtime
WORKDIR /app
ENV NODE_ENV=production
COPY --from=build /app/package.json ./package.json
COPY --from=build /app/node_modules ./node_modules
COPY --from=build /app/packages ./packages
EXPOSE 3000 4173
CMD ["node", "packages/tagengine/dist/server.js"]
