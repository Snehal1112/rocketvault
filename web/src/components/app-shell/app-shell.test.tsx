import { QueryClient, QueryClientProvider } from "@tanstack/react-query"
import {
  createMemoryHistory,
  createRootRoute,
  createRoute,
  createRouter,
  RouterProvider,
} from "@tanstack/react-router"
import { render, screen } from "@testing-library/react"
import { describe, expect, it } from "vitest"

import { AppShell } from "@/components/app-shell/app-shell"
import { ThemeProvider } from "@/components/theme-provider"

function createTestRouter(initialPath: string) {
  const testRootRoute = createRootRoute()
  const vaultRoute = createRoute({
    getParentRoute: () => testRootRoute,
    path: "/vaults/$vaultName/secrets",
    component: () => (
      <AppShell>
        <div>vault content</div>
      </AppShell>
    ),
  })
  const adminRoute = createRoute({
    getParentRoute: () => testRootRoute,
    path: "/admin/users",
    component: () => (
      <AppShell>
        <div>admin content</div>
      </AppShell>
    ),
  })
  const routeTree = testRootRoute.addChildren([vaultRoute, adminRoute])

  return createRouter({
    routeTree,
    basepath: "/app",
    history: createMemoryHistory({ initialEntries: [initialPath] }),
  })
}

function renderAt(path: string) {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  })
  const router = createTestRouter(path)
  return render(
    <ThemeProvider>
      <QueryClientProvider client={queryClient}>
        <RouterProvider router={router} />
      </QueryClientProvider>
    </ThemeProvider>
  )
}

describe("AppShell", () => {
  it("shows vault-mode nav and hides admin-mode nav at a vault route", async () => {
    renderAt("/app/vaults/prod/secrets")

    expect(
      await screen.findByRole("link", { name: /secrets/i })
    ).toBeInTheDocument()
    expect(
      screen.queryByRole("link", { name: /overview/i })
    ).not.toBeInTheDocument()
  })

  it("shows admin-mode nav and hides vault-mode nav at an admin route", async () => {
    renderAt("/app/admin/users")

    expect(
      await screen.findByRole("link", { name: /overview/i })
    ).toBeInTheDocument()
    expect(
      screen.queryByRole("link", { name: /secrets/i })
    ).not.toBeInTheDocument()
  })
})
