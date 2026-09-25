import { QueryClient, QueryClientProvider } from "@tanstack/react-query"
import {
  createMemoryHistory,
  createRootRoute,
  createRoute,
  createRouter,
  RouterProvider,
} from "@tanstack/react-router"
import { render, screen, within } from "@testing-library/react"
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

/**
 * Scoped to the sidebar: since the TopBar breadcrumb also renders the
 * current section (and shadcn's BreadcrumbPage carries role="link"), an
 * unscoped byRole("link") query would match both.
 */
async function findSidebarNav() {
  await screen.findAllByRole("link")
  const content = document.querySelector<HTMLElement>(
    '[data-slot="sidebar-content"]'
  )
  if (!content) {
    throw new Error("sidebar content did not render")
  }
  return within(content)
}

describe("AppShell", () => {
  it("shows vault-mode nav and hides admin-mode nav at a vault route", async () => {
    renderAt("/app/vaults/prod/secrets")
    const nav = await findSidebarNav()

    expect(nav.getByRole("link", { name: /secrets/i })).toBeInTheDocument()
    expect(
      nav.queryByRole("link", { name: /overview/i })
    ).not.toBeInTheDocument()
  })

  it("shows admin-mode nav and hides vault-mode nav at an admin route", async () => {
    renderAt("/app/admin/users")
    const nav = await findSidebarNav()

    expect(nav.getByRole("link", { name: /overview/i })).toBeInTheDocument()
    expect(
      nav.queryByRole("link", { name: /secrets/i })
    ).not.toBeInTheDocument()
  })

  it("renders the full breadcrumb path for the current vault page", async () => {
    renderAt("/app/vaults/prod/secrets")

    const breadcrumb = within(
      await screen.findByRole("navigation", { name: /breadcrumb/i })
    )
    expect(breadcrumb.getByRole("link", { name: "Vaults" })).toHaveAttribute(
      "href",
      "/app/vaults"
    )
    expect(breadcrumb.getByRole("link", { name: "prod" })).toHaveAttribute(
      "href",
      "/app/vaults/prod/secrets"
    )
    expect(breadcrumb.getByText("Secrets")).toHaveAttribute(
      "aria-current",
      "page"
    )
  })
})
