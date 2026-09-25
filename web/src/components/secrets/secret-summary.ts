import type { Secret } from "@/api/secrets"

export interface SecretSummary {
  total: number
  enabled: number
  /** null when the deleted-secrets list could not be read -- see below. */
  deleted: number | null
}

/**
 * Counts for the stat row above the secrets grid (visual design language
 * doc, rule 3).
 *
 * The doc suggests total / expiring soon / deleted, but "expiring soon" is
 * not derivable here: the list endpoint never populates expires_at
 * (../../../api/secrets.go:192-199 projects only id, name, tags, version,
 * created_at and enabled), so the only honest way to compute it would be an
 * extra GET per secret. Enabled is shown instead -- it is in the list
 * payload and is what an operator scanning for a broken integration wants.
 *
 * `deleted` stays null rather than collapsing to 0 when the deleted-items
 * list is unavailable: listing deleted secrets is a separate data action, so
 * a caller without it must not be shown "0 deleted" as though that were a
 * measured fact.
 */
export function summarizeSecrets(
  secrets: Secret[],
  deletedCount: number | null
): SecretSummary {
  return {
    total: secrets.length,
    enabled: secrets.filter((item) => item.enabled).length,
    deleted: deletedCount,
  }
}

/** Client-side name/tag filter over the already-fetched page. */
export function filterSecrets(secrets: Secret[], query: string): Secret[] {
  const needle = query.trim().toLowerCase()
  if (!needle) {
    return secrets
  }

  return secrets.filter((item) => {
    if (item.name.toLowerCase().includes(needle)) {
      return true
    }
    return (item.tags ?? []).some((tag) => tag.toLowerCase().includes(needle))
  })
}
