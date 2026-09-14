import { defineConfig, mergeConfig } from "vitest/config"

import viteConfig from "./vite.config.ts"

export default mergeConfig(
  viteConfig,
  defineConfig({
    test: {
      environment: "jsdom",
      setupFiles: ["./src/test/setup.ts"],
      globals: false,
      // The suite is component-heavy: a file's FIRST test pays for jsdom
      // setup, React, the router and userEvent all at once, and under the
      // parallelism of a full run that regularly crossed vitest's 5s
      // default. The failures were always the first `it` in a file and
      // moved between files run to run -- contention, not slow assertions.
      // Every file still passes on its own; this makes the full run agree.
      testTimeout: 20_000,
    },
  })
)
