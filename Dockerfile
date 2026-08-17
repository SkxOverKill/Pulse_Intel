# syntax=docker/dockerfile:1

# Pulse Intelligence — single image for both the web app and the worker.
# The `docker-compose.yml` `full` profile runs this image twice: once with the
# default CMD (`npm run start`) for the Next.js production server, and once with
# `command: ["npm", "run", "worker"]` for the BullMQ background worker.
#
# The runtime stage deliberately keeps the full `node_modules` (dev deps
# included) because operator tooling ships in the same image: `attack:sync`,
# `cve:catchup`, `db:seed*`, and the verify scripts all execute via `tsx`, which
# is a devDependency. A containerised deploy should be able to run those
# maintenance jobs inside the running image, not on the host.

FROM node:24-slim AS build

WORKDIR /app
ENV NEXT_TELEMETRY_DISABLED=1
ARG DATABASE_URL=postgresql://postgres:postgres@localhost:5432/pulse
ENV DATABASE_URL=$DATABASE_URL

# OpenSSL is required by Prisma's schema/migration engine — node:24-slim omits
# it, and prisma warns (then degrades) without it.
RUN apt-get update && apt-get install -y --no-install-recommends openssl \
  && rm -rf /var/lib/apt/lists/*

# prisma.config.ts + prisma/ must exist before `npm ci` — the postinstall hook
# runs `prisma generate`, which reads the schema and output path from them.
COPY package.json package-lock.json prisma.config.ts tsconfig.json ./
COPY prisma ./prisma
RUN npm ci

COPY . .
# The postinstall already generated the client, but run it again after the
# source lands so `next build` and the worker see an authoritative copy.
RUN npm run db:generate
RUN npm run build

# --- runtime ---------------------------------------------------------------

FROM node:24-slim AS runtime

WORKDIR /app
ENV NODE_ENV=production
ENV NEXT_TELEMETRY_DISABLED=1

RUN apt-get update && apt-get install -y --no-install-recommends openssl \
  && rm -rf /var/lib/apt/lists/*

COPY --from=build /app/package.json /app/package-lock.json /app/prisma.config.ts /app/tsconfig.json ./
COPY --from=build /app/prisma ./prisma
COPY --from=build /app/node_modules ./node_modules
COPY --from=build /app/.next ./.next
COPY --from=build /app/public ./public
COPY --from=build /app/next.config.ts ./
COPY --from=build /app/src ./src
COPY --from=build /app/scripts ./scripts

COPY docker-entrypoint.sh /usr/local/bin/pulse-entrypoint
RUN chmod +x /usr/local/bin/pulse-entrypoint

EXPOSE 3000

ENTRYPOINT ["pulse-entrypoint"]
CMD ["npm", "run", "start"]