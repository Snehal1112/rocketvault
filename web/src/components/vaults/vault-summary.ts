import type { Vault } from "@/api/vaults"

export interface VaultSummary {
  total: number
  enabled: number
  disabled: number
}

/**
 * Counts for the stat row above the vault grid (visual design language
 * doc, rule 3). Soft-deleted vaults are excluded from every count -- the
 * picker only lists live vaults, so counting deleted ones would make the
 * total disagree with the cards below it.
 */
export function summarizeVaults(vaults: Vault[]): VaultSummary {
  const live = vaults.filter((vault) => !vault.deletedAt)
  const enabled = live.filter((vault) => vault.enabled).length
  return {
    total: live.length,
    enabled,
    disabled: live.length - enabled,
  }
}
