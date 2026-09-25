import { cleanup, configure } from "@testing-library/react"
import "@testing-library/jest-dom/vitest"
import { afterEach } from "vitest"

// findBy*/waitFor default to 1s, which is separate from vitest's own
// testTimeout and is not raised by it. Under the parallelism of a full run
// a first render plus its query resolution regularly crossed that second,
// so component tests failed while still showing their loading skeleton --
// and passed when run file by file. Five seconds is still short enough that
// a genuinely stuck query fails the test rather than hanging the suite.
configure({ asyncUtilTimeout: 5000 })

// vitest.config.ts runs with `globals: false`, so React Testing Library's
// own auto-cleanup (which relies on detecting a global `afterEach`) never
// registers -- do it explicitly so each test starts from an empty document.
afterEach(() => {
  cleanup()
})

// jsdom does not implement elementFromPoint, which input-otp's hover
// tracking calls on a timer; without a stub it throws an unhandled
// exception in any test that renders <InputOTP>.
if (!document.elementFromPoint) {
  document.elementFromPoint = () => null
}

// jsdom does not implement matchMedia, which theme-provider.tsx (and any
// component using useTheme()) calls to resolve the "system" theme.
if (!window.matchMedia) {
  window.matchMedia = (query: string) => ({
    matches: false,
    media: query,
    onchange: null,
    addListener: () => {},
    removeListener: () => {},
    addEventListener: () => {},
    removeEventListener: () => {},
    dispatchEvent: () => false,
  })
}
