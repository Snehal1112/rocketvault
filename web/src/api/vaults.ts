import { request } from "@/api/client"

// Route shapes verified against ../../../api/vault.go and
// ../../../internal/services/vaults/vault_service.go directly (Epic 01
// plan, Task 1) -- not guessed. InitVault registers POST/GET /vaults,
// GET/PATCH/DELETE /vaults/{name}, PUT/GET/DELETE /vaults/{name}/webhook,
// and DELETE /vaults/{vault_name}/purge. There is NO recover route:
// VaultService.RecoverVault exists at the service layer (vault_service.go)
// but api/vault.go never wires it to an HTTP handler. This is a real
// backend gap, not an oversight here -- no recoverVault() is exported by
// this module, and the vault settings page (Task 4) does not build a
// recover action as a result.

interface VaultResponseBody {
  id: string
  name: string
  enabled: boolean
  purge_protection: boolean
  retention_days: number
  created_by: string
  created_at: string
  deleted_at?: string
  scheduled_purge_at?: string
  tags?: Record<string, string>
  updated_at?: string
  updated_by?: string
}

export interface Vault {
  id: string
  name: string
  enabled: boolean
  purgeProtection: boolean
  retentionDays: number
  createdBy: string
  createdAt: string
  deletedAt?: string
  scheduledPurgeAt?: string
  tags?: Record<string, string>
  updatedAt?: string
  updatedBy?: string
}

function mapVault(body: VaultResponseBody): Vault {
  return {
    id: body.id,
    name: body.name,
    enabled: body.enabled,
    purgeProtection: body.purge_protection,
    retentionDays: body.retention_days,
    createdBy: body.created_by,
    createdAt: body.created_at,
    deletedAt: body.deleted_at,
    scheduledPurgeAt: body.scheduled_purge_at,
    tags: body.tags,
    updatedAt: body.updated_at,
    updatedBy: body.updated_by,
  }
}

/** GET /vaults, optionally including soft-deleted vaults. */
export async function listVaults(includeDeleted?: boolean): Promise<Vault[]> {
  const path = includeDeleted ? "/vaults?include_deleted=true" : "/vaults"
  const body = await request<{
    vaults: VaultResponseBody[]
    total: number
  }>(path)
  return body.vaults.map(mapVault)
}

/** GET /vaults/{name}. */
export async function getVault(name: string): Promise<Vault> {
  const body = await request<VaultResponseBody>(
    `/vaults/${encodeURIComponent(name)}`
  )
  return mapVault(body)
}

export interface CreateVaultInput {
  name: string
  enabled?: boolean
  purgeProtection?: boolean
  retentionDays?: number
  tags?: Record<string, string>
}

/** POST /vaults. */
export async function createVault(input: CreateVaultInput): Promise<Vault> {
  const body = await request<VaultResponseBody>("/vaults", {
    method: "POST",
    body: JSON.stringify({
      name: input.name,
      enabled: input.enabled,
      purge_protection: input.purgeProtection,
      retention_days: input.retentionDays,
      tags: input.tags,
    }),
  })
  return mapVault(body)
}

export interface UpdateVaultInput {
  enabled?: boolean
  purgeProtection?: boolean
  retentionDays?: number
  tags?: Record<string, string>
}

/**
 * PATCH /vaults/{name}. Only explicitly-passed fields are included in the
 * request body -- an unset field is omitted entirely, not sent as
 * null/"" -- mirroring both the CLI's "only explicitly-passed flags
 * applied" behavior and the backend's UpdateVaultRequest, where a nil
 * field means unchanged.
 */
export async function updateVault(
  name: string,
  patch: UpdateVaultInput
): Promise<Vault> {
  const requestBody: Record<string, unknown> = {}
  if (patch.enabled !== undefined) {
    requestBody.enabled = patch.enabled
  }
  if (patch.purgeProtection !== undefined) {
    requestBody.purge_protection = patch.purgeProtection
  }
  if (patch.retentionDays !== undefined) {
    requestBody.retention_days = patch.retentionDays
  }
  if (patch.tags !== undefined) {
    requestBody.tags = patch.tags
  }

  const body = await request<VaultResponseBody>(
    `/vaults/${encodeURIComponent(name)}`,
    { method: "PATCH", body: JSON.stringify(requestBody) }
  )
  return mapVault(body)
}

/** DELETE /vaults/{name} -- soft-delete. */
export async function deleteVault(name: string): Promise<void> {
  await request(`/vaults/${encodeURIComponent(name)}`, { method: "DELETE" })
}

/** DELETE /vaults/{name}/purge -- permanent. */
export async function purgeVault(name: string): Promise<void> {
  await request(`/vaults/${encodeURIComponent(name)}/purge`, {
    method: "DELETE",
  })
}
