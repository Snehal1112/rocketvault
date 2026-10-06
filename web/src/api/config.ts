import { request } from "@/api/client"

// Mirrors app.FrontendConfig (../../../app/app.go) verbatim -- snake_case,
// unlike auth.ts's camelCased login/refresh results -- because Task 6's
// login form reads this shape directly as config.feature_flags.oidc_enabled.
export interface FrontendConfig {
  feature_flags: Record<string, boolean>
  public_api_url: string
  sentry_dsn: string
}

/** GET /config. Public route -- see src/api/client.ts's PUBLIC_PATHS. */
export async function getConfig(): Promise<FrontendConfig> {
  return request<FrontendConfig>("/config")
}
