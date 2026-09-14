import type { LinkProps } from "@tanstack/react-router"

export interface BreadcrumbSegment {
  label: string
  /** Renders the label in font-heading -- identifiers only (design
   * language rule 1: names and IDs are monospace, prose is not). */
  mono?: boolean
  /** Absent on the last segment, which is the current page. */
  link?: LinkProps
}

const VAULT_SECTION_LABELS: Record<string, string> = {
  secrets: "Secrets",
  keys: "Keys",
  settings: "Settings",
}

const UUID_PATTERN =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i

/**
 * Keys and certificates are addressed by UUID, not by name, so a raw
 * identifier crumb would be 36 characters of noise. The first block is
 * already enough to recognise which item you are on; the full id is on the
 * page itself.
 */
function abbreviateIdentifier(segment: string): string {
  return UUID_PATTERN.test(segment) ? `${segment.slice(0, 8)}…` : segment
}

/**
 * Only sections whose route actually exists get a link. An Epic-02+ path
 * that lands here before its route is built still renders a readable
 * crumb, it just isn't clickable -- better than linking somewhere that
 * 404s.
 */
function vaultSectionLink(
  section: string,
  vaultName: string
): LinkProps | undefined {
  if (section === "secrets") {
    return { to: "/vaults/$vaultName/secrets", params: { vaultName } }
  }
  if (section === "keys") {
    return { to: "/vaults/$vaultName/keys", params: { vaultName } }
  }
  if (section === "settings") {
    return { to: "/vaults/$vaultName/settings", params: { vaultName } }
  }
  return undefined
}

function titleCase(segment: string) {
  const spaced = segment.replace(/-/g, " ")
  return spaced.charAt(0).toUpperCase() + spaced.slice(1)
}

/**
 * Derives the TopBar breadcrumb trail from the router pathname (basepath
 * already stripped), e.g. "/vaults/payments/settings" ->
 * "Vaults / payments / Settings". The trailing segment is always
 * link-less: it is the page you are on.
 */
export function buildBreadcrumbs(pathname: string): BreadcrumbSegment[] {
  const parts = pathname.split("/").filter(Boolean)
  const segments: BreadcrumbSegment[] = []

  if (parts[0] === "vaults") {
    segments.push({ label: "Vaults", link: { to: "/vaults" } })

    const vaultName = parts[1]
    if (vaultName) {
      segments.push({
        label: vaultName,
        mono: true,
        link: { to: "/vaults/$vaultName/secrets", params: { vaultName } },
      })

      const section = parts[2]
      if (section) {
        segments.push({
          label: VAULT_SECTION_LABELS[section] ?? titleCase(section),
          link: vaultSectionLink(section, vaultName),
        })
      }

      // Anything deeper is a resource identifier (a secret name, a key
      // version), so it follows the monospace rule.
      for (const part of parts.slice(3)) {
        // "deleted" is a sub-tab of a section, not a resource identifier, so
        // it stays in prose rather than being rendered as a monospace name.
        if (part === "deleted") {
          segments.push({ label: "Deleted" })
          continue
        }
        segments.push({
          label: abbreviateIdentifier(decodeURIComponent(part)),
          mono: true,
        })
      }
    }
  } else if (parts[0] === "admin") {
    segments.push({ label: "Admin", link: { to: "/admin" } })
    for (const part of parts.slice(1)) {
      segments.push({ label: titleCase(part) })
    }
  } else if (parts.length > 0) {
    segments.push({ label: titleCase(parts[0]) })
  } else {
    segments.push({ label: "RocketVault" })
  }

  const last = segments[segments.length - 1]
  if (last?.link) {
    segments[segments.length - 1] = { label: last.label, mono: last.mono }
  }

  return segments
}
