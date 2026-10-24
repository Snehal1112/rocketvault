import { request } from "@/api/client"
import { ApiError } from "@/api/types"
import { getAccessToken } from "@/lib/auth/auth-context"

// Route shapes and field names verified against ../../../api/secrets.go,
// api/secrets_versions.go, api/secrets_transfer.go, api/soft_delete.go,
// api/backup_item.go and model/secret.go directly -- not guessed.
//
// Two backend facts shape this whole module:
//
//  1. Every secret path parameter is a UUID, never a name
//     (api/secrets.go:62 registers "{secret_id:[A-Fa-f0-9-]+}"). There is
//     no name-addressed secret route, so the UI keeps the id from the list
//     response and addresses everything by it.
//  2. The list response deliberately omits value, content_type, expires_at
//     and not_before (api/secrets.go:192-199 never sets them), so the
//     detail screen has to issue its own getSecret call.

const API_PREFIX = "/vaults"

function vaultPath(vaultName: string, suffix: string): string {
  return `${API_PREFIX}/${encodeURIComponent(vaultName)}${suffix}`
}

interface SecretResponseBody {
  id: string
  name: string
  value?: string
  tags?: string[]
  version: number
  content_type?: string
  created_at: string
  updated_at?: string
  enabled: boolean
  expires_at?: string
  not_before?: string
}

export interface Secret {
  id: string
  name: string
  /** Only ever populated by getSecret and generateSecret. */
  value?: string
  tags?: string[]
  version: number
  contentType?: string
  createdAt: string
  updatedAt?: string
  enabled: boolean
  expiresAt?: string
  notBefore?: string
}

function mapSecret(body: SecretResponseBody): Secret {
  return {
    id: body.id,
    name: body.name,
    value: body.value,
    tags: body.tags,
    version: body.version,
    contentType: body.content_type,
    createdAt: body.created_at,
    updatedAt: body.updated_at,
    enabled: body.enabled,
    expiresAt: body.expires_at,
    notBefore: body.not_before,
  }
}

/**
 * The content types the backend accepts, verbatim from its allowlist
 * (internal/services/secrets/secret_service.go:73-81). Anything else is a
 * 400, so the UI offers exactly these and nothing more.
 */
export const SECRET_CONTENT_TYPES: ReadonlyArray<{
  value: string
  label: string
}> = [
  { value: "", label: "None" },
  { value: "text/plain", label: "text/plain" },
  { value: "application/json", label: "application/json" },
  { value: "application/xml", label: "application/xml" },
  { value: "application/x-pem-file", label: "application/x-pem-file" },
  { value: "application/x-pkcs12", label: "application/x-pkcs12" },
  { value: "application/octet-stream", label: "application/octet-stream" },
]

export interface ListSecretsOptions {
  tags?: string[]
  /** 0-based -- the backend computes offset as page * per_page. */
  page?: number
  /** Backend default 60, hard-capped at 200 (api/params.go:56-77). */
  perPage?: number
}

/** The backend's hard cap on per_page; asking for more silently yields 200. */
export const MAX_SECRETS_PER_PAGE = 200

/**
 * GET /vaults/{vault}/secrets. The response envelope's `total` is the
 * length of THIS page, not a grand row count (model/secret.go:274-275), so
 * it carries no information the array doesn't and is not surfaced here.
 */
export async function listSecrets(
  vaultName: string,
  options: ListSecretsOptions = {}
): Promise<Secret[]> {
  const params = new URLSearchParams()
  if (options.tags && options.tags.length > 0) {
    params.set("tags", options.tags.join(","))
  }
  if (options.page !== undefined) {
    params.set("page", String(options.page))
  }
  if (options.perPage !== undefined) {
    params.set("per_page", String(options.perPage))
  }

  const query = params.toString()
  const body = await request<{ secrets: SecretResponseBody[]; total: number }>(
    vaultPath(vaultName, `/secrets${query ? `?${query}` : ""}`)
  )
  return body.secrets.map(mapSecret)
}

/** GET /vaults/{vault}/secrets/{id} -- the only list-shaped call that
 * returns the plaintext value. */
export async function getSecret(
  vaultName: string,
  secretId: string
): Promise<Secret> {
  const body = await request<SecretResponseBody>(
    vaultPath(vaultName, `/secrets/${encodeURIComponent(secretId)}`)
  )
  return mapSecret(body)
}

export interface CreateSecretInput {
  name: string
  value: string
  tags?: string[]
  contentType?: string
  enabled?: boolean
  expiresAt?: string
  notBefore?: string
  purgeProtection?: boolean
}

/** POST /vaults/{vault}/secrets. */
export async function createSecret(
  vaultName: string,
  input: CreateSecretInput
): Promise<Secret> {
  const requestBody: Record<string, unknown> = {
    name: input.name,
    value: input.value,
  }
  if (input.tags !== undefined) {
    requestBody.tags = input.tags
  }
  if (input.contentType !== undefined) {
    requestBody.content_type = input.contentType
  }
  if (input.enabled !== undefined) {
    requestBody.enabled = input.enabled
  }
  if (input.expiresAt !== undefined) {
    requestBody.expires_at = input.expiresAt
  }
  if (input.notBefore !== undefined) {
    requestBody.not_before = input.notBefore
  }
  if (input.purgeProtection !== undefined) {
    requestBody.purge_protection = input.purgeProtection
  }

  const body = await request<SecretResponseBody>(
    vaultPath(vaultName, "/secrets"),
    { method: "POST", body: JSON.stringify(requestBody) }
  )
  return mapSecret(body)
}

export interface UpdateSecretInput {
  name?: string
  value?: string
  tags?: string[]
  contentType?: string
  enabled?: boolean
  expiresAt?: string
  notBefore?: string
  purgeProtection?: boolean
}

/**
 * PUT /vaults/{vault}/secrets/{id}. Only explicitly-passed fields are sent;
 * the backend treats an absent field as "unchanged". Note the backend's own
 * asymmetry (model/secret.go:205-215): name and value are plain strings
 * there, so an empty string means "no change" and neither can be cleared
 * through this endpoint. Sending no changes at all is a 400.
 */
export async function updateSecret(
  vaultName: string,
  secretId: string,
  patch: UpdateSecretInput
): Promise<Secret> {
  const requestBody: Record<string, unknown> = {}
  if (patch.name !== undefined) {
    requestBody.name = patch.name
  }
  if (patch.value !== undefined) {
    requestBody.value = patch.value
  }
  if (patch.tags !== undefined) {
    requestBody.tags = patch.tags
  }
  if (patch.contentType !== undefined) {
    requestBody.content_type = patch.contentType
  }
  if (patch.enabled !== undefined) {
    requestBody.enabled = patch.enabled
  }
  if (patch.expiresAt !== undefined) {
    requestBody.expires_at = patch.expiresAt
  }
  if (patch.notBefore !== undefined) {
    requestBody.not_before = patch.notBefore
  }
  if (patch.purgeProtection !== undefined) {
    requestBody.purge_protection = patch.purgeProtection
  }

  const body = await request<SecretResponseBody>(
    vaultPath(vaultName, `/secrets/${encodeURIComponent(secretId)}`),
    { method: "PUT", body: JSON.stringify(requestBody) }
  )
  return mapSecret(body)
}

/** DELETE /vaults/{vault}/secrets/{id} -- soft-delete, recoverable. */
export async function deleteSecret(
  vaultName: string,
  secretId: string
): Promise<void> {
  await request(
    vaultPath(vaultName, `/secrets/${encodeURIComponent(secretId)}`),
    { method: "DELETE" }
  )
}

export interface GenerateSecretInput {
  name: string
  /** Backend default 16, accepted range 8-128 (api/secrets.go:443-449). */
  length?: number
  useSymbols?: boolean
  useNumbers?: boolean
  useUppercase?: boolean
  useLowercase?: boolean
}

/**
 * POST /vaults/{vault}/secrets/generate. This is a SERVER-side generate:
 * the value is produced by the backend and stored as a real secret. It is
 * deliberately not a local "generate a password" helper -- there is no
 * client-side RNG path in this module.
 */
export async function generateSecret(
  vaultName: string,
  input: GenerateSecretInput
): Promise<Secret> {
  const requestBody: Record<string, unknown> = { name: input.name }
  if (input.length !== undefined) {
    requestBody.length = input.length
  }
  if (input.useSymbols !== undefined) {
    requestBody.use_symbols = input.useSymbols
  }
  if (input.useNumbers !== undefined) {
    requestBody.use_numbers = input.useNumbers
  }
  if (input.useUppercase !== undefined) {
    requestBody.use_uppercase = input.useUppercase
  }
  if (input.useLowercase !== undefined) {
    requestBody.use_lowercase = input.useLowercase
  }

  const body = await request<SecretResponseBody>(
    vaultPath(vaultName, "/secrets/generate"),
    { method: "POST", body: JSON.stringify(requestBody) }
  )
  return mapSecret(body)
}

// -- Versions ---------------------------------------------------------------

interface SecretVersionMetadataBody {
  id: string
  secret_id: string
  name: string
  version: number
  created_at: string
}

export interface SecretVersionMetadata {
  id: string
  secretId: string
  name: string
  version: number
  createdAt: string
}

interface SecretVersionBody extends SecretVersionMetadataBody {
  user_id: string
  value: string
}

export interface SecretVersion extends SecretVersionMetadata {
  userId: string
  value: string
}

function mapVersionMetadata(
  body: SecretVersionMetadataBody
): SecretVersionMetadata {
  return {
    id: body.id,
    secretId: body.secret_id,
    name: body.name,
    version: body.version,
    createdAt: body.created_at,
  }
}

function mapVersion(body: SecretVersionBody): SecretVersion {
  return {
    ...mapVersionMetadata(body),
    userId: body.user_id,
    value: body.value,
  }
}

/**
 * GET /vaults/{vault}/secrets/{id}/versions -- a BARE array, not an
 * envelope (api/secrets_versions.go:59). Carries metadata only; historical
 * values are never decrypted on this path by design.
 */
export async function listSecretVersions(
  vaultName: string,
  secretId: string
): Promise<SecretVersionMetadata[]> {
  const body = await request<SecretVersionMetadataBody[]>(
    vaultPath(vaultName, `/secrets/${encodeURIComponent(secretId)}/versions`)
  )
  return body.map(mapVersionMetadata)
}

/** GET /vaults/{vault}/secrets/{id}/versions/{version} -- includes the
 * decrypted value for that one version. */
export async function getSecretVersion(
  vaultName: string,
  secretId: string,
  version: number
): Promise<SecretVersion> {
  const body = await request<SecretVersionBody>(
    vaultPath(
      vaultName,
      `/secrets/${encodeURIComponent(secretId)}/versions/${version}`
    )
  )
  return mapVersion(body)
}

/** GET /vaults/{vault}/secrets/{id}/versions/latest. */
export async function getLatestSecretVersion(
  vaultName: string,
  secretId: string
): Promise<SecretVersion> {
  const body = await request<SecretVersionBody>(
    vaultPath(
      vaultName,
      `/secrets/${encodeURIComponent(secretId)}/versions/latest`
    )
  )
  return mapVersion(body)
}

// -- Backup / restore -------------------------------------------------------

/**
 * POST /vaults/{vault}/secrets/{id}/backup. Returns the base64url blob
 * string the backend wraps in {"blob": "..."}.
 *
 * The blob is base64-ENCODED, not encrypted, and contains every historical
 * plaintext value of the secret (internal/backup/item_backup.go:152-156).
 * docs/api-specification.yaml:1885 calls it "encrypted"; the code does not.
 * Anything in the UI that hands this to the user must say so.
 */
export async function backupSecret(
  vaultName: string,
  secretId: string
): Promise<string> {
  const body = await request<{ blob: string }>(
    vaultPath(vaultName, `/secrets/${encodeURIComponent(secretId)}/backup`),
    { method: "POST" }
  )
  return body.blob
}

/**
 * POST /vaults/{vault}/secrets/restore. The restored secret gets a fresh
 * UUID which the backend does not return (api/backup_item.go:137), so the
 * caller has to re-list to find it.
 */
export async function restoreSecret(
  vaultName: string,
  blob: string
): Promise<void> {
  await request(vaultPath(vaultName, "/secrets/restore"), {
    method: "POST",
    body: JSON.stringify({ blob }),
  })
}

// -- Soft-delete ------------------------------------------------------------

interface DeletedSecretBody {
  id: string
  name: string
  version: number
  created_at: string
  deleted_at: string | null
}

export interface DeletedSecret {
  id: string
  name: string
  version: number
  createdAt: string
  deletedAt: string | null
}

/**
 * GET /vaults/{vault}/deleted/secrets. Deleted-secret rows carry five
 * fields only -- unlike deleted keys and certificates they expose neither
 * purge_protection nor a scheduled purge date (api/soft_delete.go:185-191),
 * so a purge button cannot be pre-disabled; the 403 only arrives on attempt.
 */
export async function listDeletedSecrets(
  vaultName: string
): Promise<DeletedSecret[]> {
  const body = await request<{
    deleted_secrets: DeletedSecretBody[]
    total: number
  }>(vaultPath(vaultName, "/deleted/secrets"))
  return body.deleted_secrets.map((item) => ({
    id: item.id,
    name: item.name,
    version: item.version,
    createdAt: item.created_at,
    deletedAt: item.deleted_at,
  }))
}

/** POST /vaults/{vault}/deleted/secrets/{id}/restore -- recovers a
 * soft-deleted secret. */
export async function restoreDeletedSecret(
  vaultName: string,
  secretId: string
): Promise<void> {
  await request(
    vaultPath(
      vaultName,
      `/deleted/secrets/${encodeURIComponent(secretId)}/restore`
    ),
    { method: "POST" }
  )
}

/** DELETE /vaults/{vault}/deleted/secrets/{id}/purge -- permanent. */
export async function purgeSecret(
  vaultName: string,
  secretId: string
): Promise<void> {
  await request(
    vaultPath(
      vaultName,
      `/deleted/secrets/${encodeURIComponent(secretId)}/purge`
    ),
    { method: "DELETE" }
  )
}

// -- Import / export --------------------------------------------------------

// Export and import are the only two secrets calls that cannot go through
// src/api/client.ts's request(): export answers with text/csv or a raw JSON
// array as a file download, and parseSuccessBody (client.ts:51-57)
// JSON.parses every body; import sends multipart/form-data, and buildHeaders
// (client.ts:21-30) forces Content-Type: application/json onto any request
// with a body, which would strip the multipart boundary. This helper is the
// narrow exception -- it attaches the same bearer token but deliberately
// does NOT take part in the 401-refresh-retry flow, so a request made with
// a just-expired token fails rather than silently refreshing.
async function rawRequest(path: string, init: RequestInit): Promise<Response> {
  const headers = new Headers(init.headers)
  const token = getAccessToken()
  if (token) {
    headers.set("Authorization", `Bearer ${token}`)
  }

  const response = await fetch(`/api/v1${path}`, { ...init, headers })
  if (!response.ok) {
    // Middleware rejections (401/403/429) are plain text, not JSON
    // (internal/middleware/middleware.go:288-306), so a blind .json() here
    // would throw over the real error.
    const text = await response.text()
    let message = text || response.statusText
    try {
      const parsed = JSON.parse(text) as { message?: string; error?: string }
      message = parsed.message ?? parsed.error ?? message
    } catch {
      // Plain-text body -- use it verbatim.
    }
    throw new ApiError({ message, status_code: response.status })
  }
  return response
}

export type TransferFormat = "json" | "csv"

export interface ExportSecretsInput {
  format: TransferFormat
  encrypt?: boolean
  tags?: string[]
  includeTags?: boolean
  passphrase?: string
}

export interface ExportedSecrets {
  blob: Blob
  filename: string
}

/** Parses the unquoted filename the backend sets in Content-Disposition
 * (api/secrets_transfer.go:80-93), falling back to a sane default. */
export function parseAttachmentFilename(
  header: string | null,
  fallback: string
): string {
  if (!header) {
    return fallback
  }
  const match = /filename=(?:"([^"]+)"|([^";]+))/.exec(header)
  const name = (match?.[1] ?? match?.[2] ?? "").trim()
  return name || fallback
}

/**
 * POST /vaults/{vault}/secrets/export. The format lives in the JSON body,
 * not a query param, and the response is a file download rather than a JSON
 * envelope.
 */
export async function exportSecrets(
  vaultName: string,
  input: ExportSecretsInput
): Promise<ExportedSecrets> {
  const requestBody: Record<string, unknown> = {
    format: input.format,
    encrypt: input.encrypt ?? false,
    include_tags: input.includeTags ?? false,
  }
  if (input.tags !== undefined) {
    requestBody.tags = input.tags
  }
  if (input.passphrase) {
    requestBody.passphrase = input.passphrase
  }

  const response = await rawRequest(vaultPath(vaultName, "/secrets/export"), {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(requestBody),
  })

  return {
    blob: await response.blob(),
    filename: parseAttachmentFilename(
      response.headers.get("Content-Disposition"),
      `secrets-export.${input.format}`
    ),
  }
}

export interface ImportSecretsInput {
  file: File
  format: TransferFormat
  overwrite?: boolean
  passphrase?: string
}

export interface ImportResult {
  success: boolean
  message: string
  importedCount: number
  totalCount: number
  format: string
  importedAt: string
}

/**
 * POST /vaults/{vault}/secrets/import (multipart/form-data).
 *
 * BACKEND GAP: the service layer computes per-record outcomes --
 * secrets.ImportResult carries SkippedCount, FailedCount and a per-record
 * Errors []string (internal/services/secrets/secret_service.go:126-136) --
 * but api/secrets_transfer.go:172-179 drops all three before serialising.
 * Only imported_count vs total_count survive, so the UI cannot say WHICH
 * rows failed or distinguish skipped from failed.
 */
export async function importSecrets(
  vaultName: string,
  input: ImportSecretsInput
): Promise<ImportResult> {
  const form = new FormData()
  form.append("file", input.file)
  form.append("format", input.format)
  form.append("overwrite", input.overwrite ? "true" : "false")
  if (input.passphrase) {
    form.append("passphrase", input.passphrase)
  }

  const response = await rawRequest(vaultPath(vaultName, "/secrets/import"), {
    method: "POST",
    body: form,
  })

  const body = (await response.json()) as {
    success: boolean
    message: string
    imported_count: number
    total_count: number
    format: string
    imported_at: string
  }

  return {
    success: body.success,
    message: body.message,
    importedCount: body.imported_count,
    totalCount: body.total_count,
    format: body.format,
    importedAt: body.imported_at,
  }
}
