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
      // At the default one-worker-per-file, a 41-file suite spawned 41
      // processes on a 12-core machine and still occasionally starved a
      // file past the 20s timeout above under real load (verified: every
      // failure disappeared at --maxWorkers=4). Capping this is the actual
      // fix; the timeout above is a backstop, not a substitute for it.
      maxWorkers: 6,
    },
  })
)
