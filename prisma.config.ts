import "dotenv/config";
import { defineConfig } from "prisma/config";

export default defineConfig({
  schema: "prisma/schema.prisma",
  migrations: {
    path: "prisma/migrations",
    seed: "tsx prisma/seed.ts",
  },
  datasource: {
    url: process.env["DATABASE_URL"],
    // The local Prisma Postgres dev server cannot CREATE DATABASE for a shadow db,
    // so it exposes a dedicated shadow instance on the next port up. Without this,
    // `migrate dev` fails with P1017.
    shadowDatabaseUrl: process.env["SHADOW_DATABASE_URL"],
  },
});
