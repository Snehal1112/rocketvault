import { cleanup } from "@testing-library/react"
import "@testing-library/jest-dom/vitest"
import { afterEach } from "vitest"

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
