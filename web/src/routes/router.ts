import { createRoute, createRouter } from "@tanstack/react-router"

import { loginRoute } from "@/routes/login"
import { rootRoute } from "@/routes/__root"

// Temporary placeholder for "/" -- replaced by the real src/routes/index.tsx
// (current-vault redirect logic, Task 7) once it lands in Task 10.
const placeholderIndexRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/",
  component: () => "Loading…",
})

const routeTree = rootRoute.addChildren([placeholderIndexRoute, loginRoute])

export const router = createRouter({ routeTree, basepath: "/app" })

declare module "@tanstack/react-router" {
  interface Register {
    router: typeof router
  }
}
