// Client-side "which vault was I last in" tracking, used by the "/" route to
// decide where to redirect. This is a convenience, not an authorization
// signal -- see the design doc's Deferred section: GET /vaults only returns
// vaults the caller can manage, not every vault they hold a data-plane role
// in, so there is no server-side "my vaults" list to redirect against.

const LAST_VAULT_KEY = "rocketvault_last_vault"

export function getLastVault(): string | null {
  return localStorage.getItem(LAST_VAULT_KEY)
}

export function setLastVault(name: string): void {
  localStorage.setItem(LAST_VAULT_KEY, name)
}

/**
 * Decides where the "/" route should redirect to. An explicit vault name
 * (e.g. a `?vault=` search param on a deep link) wins over the stored
 * last-used vault; with neither, falls back to the vault picker.
 */
export function resolveIndexRedirect(
  explicitVaultName: string | null | undefined
): string {
  const vaultName = explicitVaultName ?? getLastVault()
  if (vaultName) {
    return `/vaults/${vaultName}/secrets`
  }
  return "/vaults"
}
