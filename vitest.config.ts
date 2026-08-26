import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    include: ["test/**/*.test.ts"],
    environment: "node",
    setupFiles: ["./test/vitest-setup.ts"], // keep tests off the live decision log
  },
});
