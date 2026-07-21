import { resolve } from "node:path";
import { defineConfig } from "vitest/config";

export default defineConfig({
  resolve: {
    // Mirror the tsconfig path alias. Without this, any test touching a module
    // with a runtime `@/` import fails to resolve — type-only imports get erased
    // and hide the problem until the first value import.
    alias: { "@": resolve(__dirname, "src") },
  },
  test: {
    include: ["src/**/*.test.ts"],
    environment: "node",
  },
});
