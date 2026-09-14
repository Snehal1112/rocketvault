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
