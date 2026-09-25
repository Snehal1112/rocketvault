import { redirect } from "@tanstack/react-router"

import { getAuthSnapshot } from "@/lib/auth/auth-context"
import { toast } from "@/components/ui/toast"

/**
 * Route `beforeLoad` guard: throws a redirect to /login unless the session
 * is authenticated. Per the design doc §2, a vault-scoped route's actual
 * per-vault role cannot be pre-checked here (no "which vaults am I in"
 * endpoint exists) -- this only confirms the caller is logged in at all.
 */
export function requireAuth(): void {
  const { status } = getAuthSnapshot()
  if (status !== "authenticated") {
    throw redirect({ to: "/login" })
  }
}

/**
 * Route `beforeLoad` guard for the admin branch. Unlike a vault-scoped
 * route's guard, the global admin role IS derivable purely from the
 * JWT-derived `roles` claim already present in session state, so this can
 * check it directly rather than deferring to a data call's 403.
 *
 * A failed check redirects to "/" -- not "/login", the caller IS
 * authenticated, just not authorized for this branch -- and surfaces a
 * toast rather than bouncing silently.
 */
export function requireGlobalAdmin(): void {
  const { status, user } = getAuthSnapshot()
  if (status !== "authenticated") {
    throw redirect({ to: "/login" })
  }

  const isGlobalAdmin = user?.roles.includes("admin") ?? false
  if (!isGlobalAdmin) {
    toast.add({
      title: "Admin access required",
      description: "You don't have permission to view that page.",
      type: "error",
    })
    throw redirect({ to: "/" })
  }
}

/**
 * Route `beforeLoad` guard for the public "/" landing route. An anonymous
 * visitor sees the marketing page -- this returns without throwing -- but an
 * already-authenticated session is redirected straight past it, into the
 * vault named in `vaultName` (an explicit `?vault=` search param or the
 * stored last-used vault, resolved by the caller) or the vault picker if
 * neither exists. Mirrors the real Azure Portal's behavior: a signed-in
 * session never sees marketing content.
 */
export function redirectAuthenticatedFromLanding(
  vaultName: string | null
): void {
  const { status } = getAuthSnapshot()
  if (status !== "authenticated") {
    return
  }

  if (vaultName) {
    throw redirect({
      to: "/vaults/$vaultName/secrets",
      params: { vaultName },
      replace: true,
    })
  }
  throw redirect({ to: "/vaults", replace: true })
}
