import type { Key } from "@/api/keys"
import { isHsmBacked } from "@/components/keys/key-type"

/** How far ahead an expiry has to be before it stops being worth warning
 * about. Matches the default notify-before-expiry window the backend's
 * rotation policy ships with. */
const EXPIRY_WARNING_DAYS = 30
const DAY = 24 * 60 * 60 * 1000

export interface KeyStatus {
  tone: "on" | "off" | "warning" | "danger"
  label: string
}

function parse(iso: string | undefined): number | null {
  if (!iso) {
    return null
  }
  const parsed = Date.parse(iso)
  return Number.isNaN(parsed) ? null : parsed
}

/**
 * The single status a key card or row shows, worst-first: a revoked key is
 * revoked no matter what else is true of it, and an unparseable timestamp is
 * ignored rather than rendered as a bogus expiry state.
 */
export function keyStatusOf(key: Key, now: Date = new Date()): KeyStatus {
  if (key.revoked) {
    return { tone: "danger", label: "Revoked" }
  }
  if (!key.enabled) {
    return { tone: "off", label: "Disabled" }
  }

  const current = now.getTime()
  const expiresAt = parse(key.expiresAt)
  if (expiresAt !== null) {
    if (expiresAt <= current) {
      return { tone: "danger", label: "Expired" }
    }
    if (expiresAt - current <= EXPIRY_WARNING_DAYS * DAY) {
      return { tone: "warning", label: "Expiring soon" }
    }
  }

  const notBefore = parse(key.notBefore)
  if (notBefore !== null && notBefore > current) {
    return { tone: "warning", label: "Not yet valid" }
  }

  return { tone: "on", label: "Enabled" }
}

export interface KeysSummary {
  total: number
  hsmBacked: number
  expiringSoon: number
  /** Revoked, disabled, expired, or not yet valid -- anything an operator
   * cannot successfully sign or decrypt with right now. */
  unavailable: number
}

/** Counts for the stat row above the key grid (visual design language doc,
 * rule 3). */
export function summarizeKeys(
  keys: Key[],
  now: Date = new Date()
): KeysSummary {
  let hsmBacked = 0
  let expiringSoon = 0
  let unavailable = 0

  for (const key of keys) {
    if (isHsmBacked(key.type)) {
      hsmBacked += 1
    }
    const status = keyStatusOf(key, now)
    if (status.label === "Expiring soon") {
      expiringSoon += 1
    }
    if (status.tone === "danger" || status.tone === "off") {
      unavailable += 1
    }
  }

  return { total: keys.length, hsmBacked, expiringSoon, unavailable }
}
