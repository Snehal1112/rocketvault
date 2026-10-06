import { useQuery } from "@tanstack/react-query"

import { getConfig } from "@/api/config"
import { Button } from "@/components/ui/button"

/**
 * Renders an "Sign in with SSO" button only when the backend advertises
 * `feature_flags.oidc_enabled` via GET /config. As of this writing that flag
 * does not exist server-side yet (design doc §Deferred) -- confirmed by
 * reading api/config.go and app/app.go directly, not guessed -- so this is
 * expected to render nothing until a backend change adds it. Not a frontend
 * bug if the button never appears today.
 */
export function OidcButton() {
  const { data } = useQuery({
    queryKey: ["config"],
    queryFn: getConfig,
  })

  if (!data?.feature_flags.oidc_enabled) {
    return null
  }

  return (
    <Button
      variant="outline"
      className="w-full"
      render={<a href="/api/v1/oidc/login" />}
    >
      Sign in with SSO
    </Button>
  )
}
