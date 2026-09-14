import { createRoute, createRouter } from "@tanstack/react-router"

import { rootRoute } from "@/routes/__root"

// Temporary placeholder for "/" -- replaced by the real src/routes/index.tsx
// (current-vault redirect logic, Task 7) once it lands in Task 10.
const placeholderIndexRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/",
  component: () => "Loading…",
})

// Temporary placeholder for "/login" -- src/lib/auth/guards.ts redirects here,
// and TanStack Router's `redirect({ to })` is type-checked against the
// registered route tree, so a target route must exist before guards.ts can
// reference it. Replaced by the real src/routes/login.tsx in Task 6.
const placeholderLoginRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/login",
  component: () => "Loading…",
})

const routeTree = rootRoute.addChildren([
  placeholderIndexRoute,
  placeholderLoginRoute,
])

export const router = createRouter({ routeTree, basepath: "/app" })

declare module "@tanstack/react-router" {
  interface Register {
    router: typeof router
  }
}
