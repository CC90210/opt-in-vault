import { fileURLToPath } from "node:url";

import { defineConfig } from "vitest/config";

export default defineConfig({
  resolve: {
    alias: {
      "@": fileURLToPath(new URL("./src", import.meta.url)),
      "server-only": fileURLToPath(
        new URL("./node_modules/server-only/empty.js", import.meta.url),
      ),
    },
  },
  test: {
    globals: true,
    projects: [
      {
        extends: true,
        test: {
          name: "node",
          environment: "node",
          include: ["src/**/*.test.ts"],
        },
      },
      {
        extends: true,
        test: {
          name: "components",
          environment: "jsdom",
          include: ["src/**/*.test.tsx"],
          setupFiles: ["./src/test/setup.ts"],
        },
      },
    ],
  },
});
