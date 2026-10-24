import { createRoute } from "@tanstack/react-router"

import {
  Empty,
  EmptyDescription,
  EmptyHeader,
  EmptyTitle,
} from "@/components/ui/empty"
import { rootRoute } from "@/routes/__root"

// Stub. Real exchange logic is intentionally NOT implemented here -- verified
// against ../../../api/oidc.go directly rather than guessed: in the non-CLI
// (browser) case, oidcCallbackHandler (api/oidc.go ~L154-172) ends with
// `writeJSON(w, response)`, not an http.Redirect back to any frontend URL.
// That means the IdP's redirect_uri, as currently implemented, points at the
// BACKEND's own GET /api/v1/oidc/callback, which serves the LoginResponse
// JSON directly -- this frontend route would never actually be reached by a
// real browser OIDC flow today. Combined with feature_flags.oidc_enabled not
// existing yet (design doc §Deferred), OIDC browser SSO needs a backend
// change (redirect to something like /app/oidc/callback#token=... or set an
// HttpOnly session cookie) before this route can do anything real.
function OidcCallbackPage() {
  return (
    <Empty>
      <EmptyHeader>
        <EmptyTitle>OIDC sign-in is not available yet</EmptyTitle>
        <EmptyDescription>
          The backend does not redirect here after login -- see the comment in
          src/routes/oidc.callback.tsx.
        </EmptyDescription>
      </EmptyHeader>
    </Empty>
  )
}

export const oidcCallbackRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/oidc/callback",
  component: OidcCallbackPage,
})
