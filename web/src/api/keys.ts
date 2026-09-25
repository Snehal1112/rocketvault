import { request } from "@/api/client"

// Route shapes verified directly against the Go backend (../../../api/keys.go,
// keys_types.go, keys_crypto.go, keys_versions.go, key_rotation_policy.go,
// soft_delete.go, backup_item.go) -- not guessed. Notes that shaped this
// module:
//
//   * Every key route is registered twice: flat (/keys/...) and vault-scoped
//     (/vaults/{vault_name}/keys/...). VaultResolutionMiddleware reads the
//     vault from the PATH ONLY -- there is no header or query parameter -- and
//     falls back to the "default" vault when the path segment is absent. This
//     module therefore always uses the vault-scoped form, so a call can never
//     silently operate on the wrong vault.
//   * Keys are addressed by UUID, not by name (path var regex
//     `key_id:[A-Fa-f0-9-]+`). Unlike vaults, there is no get-by-name route.
//   * THREE different base64 encodings appear in one feature: crypto operation
//     inputs/outputs are STANDARD base64 with padding; JWK components
//     (n/e/x/y) are base64url without padding; backup blobs are base64url with
//     padding. This module passes all three through verbatim and never
//     re-encodes -- the distinction is the caller's to respect.
//   * POST /keys and POST /keys/import return 201; everything else returns 200.
//     request() does not care, so no special handling is needed here.

/** The JWK components the backend may return for a public key. This module
 * NEVER copies any other field out of a response -- so private material
 * (`d`, `p`, `q`, ...) cannot reach the UI even if a future backend change
 * started emitting it. Defense in depth, per the epic plan's Task 3. */
export interface PublicJwk {
  n?: string
  e?: string
  x?: string
  y?: string
}

interface JwkFields {
  n?: string
  e?: string
  x?: string
  y?: string
}

function mapPublicJwk(body: JwkFields): PublicJwk {
  const jwk: PublicJwk = {}
  if (body.n !== undefined) {
    jwk.n = body.n
  }
  if (body.e !== undefined) {
    jwk.e = body.e
  }
  if (body.x !== undefined) {
    jwk.x = body.x
  }
  if (body.y !== undefined) {
    jwk.y = body.y
  }
  return jwk
}

interface KeyResponseBody extends JwkFields {
  id: string
  name: string
  type: string
  user_id: string
  revoked: boolean
  created_at: string
  updated_at?: string
  // No omitempty on the Go side and the slice is nilable, so this really can
  // arrive as null rather than [].
  tags: string[] | null
  enabled: boolean
  expires_at?: string
  not_before?: string
  bits?: number
  curve?: string
}

/**
 * One key as the dashboard sees it. `type` is the value the server reports,
 * which carries an `-HSM` suffix for PKCS#11-backed keys: the full set is
 * RSA, ECDSA, ES256K, oct, RSA-HSM, EC-HSM, oct-HSM.
 */
export interface Key {
  id: string
  name: string
  type: string
  userId: string
  revoked: boolean
  createdAt: string
  updatedAt?: string
  tags: string[]
  enabled: boolean
  expiresAt?: string
  notBefore?: string
  bits?: number
  curve?: string
  /** Empty on list responses -- the backend only derives JWK components for
   * single-key reads, and never for HSM-backed keys. */
  publicJwk: PublicJwk
}

function mapKey(body: KeyResponseBody): Key {
  return {
    id: body.id,
    name: body.name,
    type: body.type,
    userId: body.user_id,
    revoked: body.revoked,
    createdAt: body.created_at,
    updatedAt: body.updated_at,
    tags: body.tags ?? [],
    enabled: body.enabled,
    expiresAt: body.expires_at,
    notBefore: body.not_before,
    bits: body.bits,
    curve: body.curve,
    publicJwk: mapPublicJwk(body),
  }
}

function keysPath(vaultName: string): string {
  return `/vaults/${encodeURIComponent(vaultName)}/keys`
}

function keyPath(vaultName: string, keyId: string): string {
  return `${keysPath(vaultName)}/${encodeURIComponent(keyId)}`
}

export interface ListKeysFilters {
  /** Exact match on the stored type string (RSA, ECDSA, ES256K, oct). */
  type?: string
  tags?: string[]
  page?: number
  /** Backend default is 60, hard-capped at 200. */
  perPage?: number
}

/** GET /vaults/{vault}/keys. */
export async function listKeys(
  vaultName: string,
  filters: ListKeysFilters = {}
): Promise<Key[]> {
  const query = new URLSearchParams()
  if (filters.type) {
    query.set("type", filters.type)
  }
  if (filters.tags && filters.tags.length > 0) {
    query.set("tags", filters.tags.join(","))
  }
  if (filters.page !== undefined) {
    query.set("page", String(filters.page))
  }
  if (filters.perPage !== undefined) {
    query.set("per_page", String(filters.perPage))
  }

  const suffix = query.size > 0 ? `?${query.toString()}` : ""
  const body = await request<{ keys: KeyResponseBody[] }>(
    `${keysPath(vaultName)}${suffix}`
  )
  return body.keys.map(mapKey)
}

/** GET /vaults/{vault}/keys/{key_id}. */
export async function getKey(vaultName: string, keyId: string): Promise<Key> {
  return mapKey(await request<KeyResponseBody>(keyPath(vaultName, keyId)))
}

/** The three types `POST /keys` accepts. OCT is HSM-gated server-side: a
 * software-backed deployment answers 400 "OCT key creation requires an
 * HSM-backed key provider". There is no client-visible `hsm.enabled` signal,
 * so OCT is offered and the server's refusal is surfaced verbatim rather than
 * pre-blocked. */
export type CreateKeyType = "RSA" | "ECDSA" | "OCT"

export type KeyCurve = "P-256" | "P-384" | "P-521" | "P-256K"

export interface CreateKeyInput {
  name: string
  type: CreateKeyType
  /** RSA: 2048 | 3072 | 4096 (defaults to 2048 server-side). OCT: 128 | 192 |
   * 256, REQUIRED -- the backend has no default and rejects 0. Ignored for
   * ECDSA. */
  bits?: number
  /** ECDSA only; defaults to P-256 server-side. */
  curve?: KeyCurve
  tags?: string[]
  enabled?: boolean
  expiresAt?: string
  notBefore?: string
  purgeProtection?: boolean
}

/** POST /vaults/{vault}/keys. */
export async function createKey(
  vaultName: string,
  input: CreateKeyInput
): Promise<Key> {
  const body: Record<string, unknown> = {
    name: input.name,
    type: input.type,
  }
  if (input.bits !== undefined) {
    body.bits = input.bits
  }
  if (input.curve !== undefined) {
    body.curve = input.curve
  }
  if (input.tags !== undefined) {
    body.tags = input.tags
  }
  if (input.enabled !== undefined) {
    body.enabled = input.enabled
  }
  if (input.expiresAt !== undefined) {
    body.expires_at = input.expiresAt
  }
  if (input.notBefore !== undefined) {
    body.not_before = input.notBefore
  }
  if (input.purgeProtection !== undefined) {
    body.purge_protection = input.purgeProtection
  }

  return mapKey(
    await request<KeyResponseBody>(keysPath(vaultName), {
      method: "POST",
      body: JSON.stringify(body),
    })
  )
}

export interface ImportKeyInput {
  name: string
  /** A PRIVATE RSA or EC JWK. The backend rejects a public-only JWK
   * (ErrJWKNoPrivateKey) and rejects `oct` JWKs outright. */
  jwk: Record<string, unknown>
  tags?: string[]
  enabled?: boolean
  expiresAt?: string
  notBefore?: string
  purgeProtection?: boolean
}

/** POST /vaults/{vault}/keys/import. */
export async function importKey(
  vaultName: string,
  input: ImportKeyInput
): Promise<Key> {
  const body: Record<string, unknown> = {
    name: input.name,
    jwk: input.jwk,
  }
  if (input.tags !== undefined) {
    body.tags = input.tags
  }
  if (input.enabled !== undefined) {
    body.enabled = input.enabled
  }
  if (input.expiresAt !== undefined) {
    body.expires_at = input.expiresAt
  }
  if (input.notBefore !== undefined) {
    body.not_before = input.notBefore
  }
  if (input.purgeProtection !== undefined) {
    body.purge_protection = input.purgeProtection
  }

  return mapKey(
    await request<KeyResponseBody>(`${keysPath(vaultName)}/import`, {
      method: "POST",
      body: JSON.stringify(body),
    })
  )
}

export interface UpdateKeyInput {
  name?: string
  revoked?: boolean
  tags?: string[]
  enabled?: boolean
  expiresAt?: string
  notBefore?: string
  purgeProtection?: boolean
}

/**
 * PUT /vaults/{vault}/keys/{key_id}. At least one field must be present or
 * the backend answers 400; only explicitly-passed fields are sent, so an
 * untouched field is omitted rather than nulled.
 */
export async function updateKey(
  vaultName: string,
  keyId: string,
  patch: UpdateKeyInput
): Promise<Key> {
  const body: Record<string, unknown> = {}
  if (patch.name !== undefined) {
    body.name = patch.name
  }
  if (patch.revoked !== undefined) {
    body.revoked = patch.revoked
  }
  if (patch.tags !== undefined) {
    body.tags = patch.tags
  }
  if (patch.enabled !== undefined) {
    body.enabled = patch.enabled
  }
  if (patch.expiresAt !== undefined) {
    body.expires_at = patch.expiresAt
  }
  if (patch.notBefore !== undefined) {
    body.not_before = patch.notBefore
  }
  if (patch.purgeProtection !== undefined) {
    body.purge_protection = patch.purgeProtection
  }

  return mapKey(
    await request<KeyResponseBody>(keyPath(vaultName, keyId), {
      method: "PUT",
      body: JSON.stringify(body),
    })
  )
}

export interface DeletedKeyReceipt {
  id: string
  name: string
  /** Always present on the wire, but nullable. */
  deletedAt?: string
  scheduledPurgeAt?: string
  recoveryId?: string
}

/** DELETE /vaults/{vault}/keys/{key_id} -- soft-delete. */
export async function deleteKey(
  vaultName: string,
  keyId: string
): Promise<DeletedKeyReceipt> {
  const body = await request<{
    id: string
    name: string
    deleted_at?: string | null
    scheduled_purge_at?: string
    recovery_id?: string
  }>(keyPath(vaultName, keyId), { method: "DELETE" })

  return {
    id: body.id,
    name: body.name,
    deletedAt: body.deleted_at ?? undefined,
    scheduledPurgeAt: body.scheduled_purge_at,
    recoveryId: body.recovery_id,
  }
}

/** POST /vaults/{vault}/keys/{key_id}/rotate -- manual rotation. Creates a new
 * current version; prior versions are retained, not destroyed. */
export async function rotateKey(
  vaultName: string,
  keyId: string
): Promise<Key> {
  return mapKey(
    await request<KeyResponseBody>(`${keyPath(vaultName, keyId)}/rotate`, {
      method: "POST",
    })
  )
}

export interface KeyVersion {
  keyId: string
  version: number
  createdAt: string
}

/** GET /vaults/{vault}/keys/{key_id}/versions. Carries no key material at all. */
export async function listKeyVersions(
  vaultName: string,
  keyId: string
): Promise<KeyVersion[]> {
  const body = await request<{
    versions: { key_id: string; version: number; created_at: string }[]
  }>(`${keyPath(vaultName, keyId)}/versions`)

  return body.versions.map((version) => ({
    keyId: version.key_id,
    version: version.version,
    createdAt: version.created_at,
  }))
}

export interface KeyVersionDetail extends KeyVersion {
  publicJwk: PublicJwk
}

/** GET /vaults/{vault}/keys/{key_id}/versions/{version}. The JWK components
 * are inlined on the version object by the backend, not nested. */
export async function getKeyVersion(
  vaultName: string,
  keyId: string,
  version: number
): Promise<KeyVersionDetail> {
  const body = await request<
    { key_id: string; version: number; created_at: string } & JwkFields
  >(`${keyPath(vaultName, keyId)}/versions/${version}`)

  return {
    keyId: body.key_id,
    version: body.version,
    createdAt: body.created_at,
    publicJwk: mapPublicJwk(body),
  }
}

// --- Crypto operations -----------------------------------------------------
//
// Every `value`/`plaintext_key`/`wrapped_key`/`signature`/`nonce` field below
// is STANDARD base64 (with padding) in both directions. `version` selects a
// specific key version; omitting it uses the current one. `verify` and
// `decrypt` have NO server-side default algorithm, so the caller must always
// supply one for those two.

export interface WrapKeyInput {
  plaintextKey: string
  algorithm: string
  version?: number
}

export interface WrapKeyResult {
  wrappedKey: string
  algorithm: string
  version: number
}

/** POST /vaults/{vault}/keys/{key_id}/wrap. */
export async function wrapKey(
  vaultName: string,
  keyId: string,
  input: WrapKeyInput
): Promise<WrapKeyResult> {
  const body = await request<{
    wrapped_key: string
    algorithm: string
    version: number
  }>(`${keyPath(vaultName, keyId)}/wrap`, {
    method: "POST",
    body: JSON.stringify({
      plaintext_key: input.plaintextKey,
      algorithm: input.algorithm,
      version: input.version,
    }),
  })

  return {
    wrappedKey: body.wrapped_key,
    algorithm: body.algorithm,
    version: body.version,
  }
}

export interface UnwrapKeyInput {
  wrappedKey: string
  algorithm: string
  version?: number
}

export interface UnwrapKeyResult {
  plaintextKey: string
  algorithm: string
  version: number
}

/** POST /vaults/{vault}/keys/{key_id}/unwrap. */
export async function unwrapKey(
  vaultName: string,
  keyId: string,
  input: UnwrapKeyInput
): Promise<UnwrapKeyResult> {
  const body = await request<{
    plaintext_key: string
    algorithm: string
    version: number
  }>(`${keyPath(vaultName, keyId)}/unwrap`, {
    method: "POST",
    body: JSON.stringify({
      wrapped_key: input.wrappedKey,
      algorithm: input.algorithm,
      version: input.version,
    }),
  })

  return {
    plaintextKey: body.plaintext_key,
    algorithm: body.algorithm,
    version: body.version,
  }
}

export interface SignInput {
  value: string
  algorithm: string
  version?: number
}

export interface SignResult {
  keyId: string
  algorithm: string
  /** The signature, standard base64. */
  value: string
  version: number
}

/** POST /vaults/{vault}/keys/{key_id}/sign. */
export async function signData(
  vaultName: string,
  keyId: string,
  input: SignInput
): Promise<SignResult> {
  const body = await request<{
    key_id: string
    algorithm: string
    value: string
    version: number
  }>(`${keyPath(vaultName, keyId)}/sign`, {
    method: "POST",
    body: JSON.stringify({
      value: input.value,
      algorithm: input.algorithm,
      version: input.version,
    }),
  })

  return {
    keyId: body.key_id,
    algorithm: body.algorithm,
    value: body.value,
    version: body.version,
  }
}

export interface VerifyInput {
  value: string
  signature: string
  algorithm: string
  version?: number
}

export interface VerifyResult {
  keyId: string
  algorithm: string
  valid: boolean
  version: number
}

/** POST /vaults/{vault}/keys/{key_id}/verify. */
export async function verifySignature(
  vaultName: string,
  keyId: string,
  input: VerifyInput
): Promise<VerifyResult> {
  const body = await request<{
    key_id: string
    algorithm: string
    valid: boolean
    version: number
  }>(`${keyPath(vaultName, keyId)}/verify`, {
    method: "POST",
    body: JSON.stringify({
      value: input.value,
      signature: input.signature,
      algorithm: input.algorithm,
      version: input.version,
    }),
  })

  return {
    keyId: body.key_id,
    algorithm: body.algorithm,
    valid: body.valid,
    version: body.version,
  }
}

export interface EncryptInput {
  value: string
  algorithm: string
  version?: number
}

export interface EncryptResult {
  keyId: string
  algorithm: string
  value: string
  /** Only returned for AEAD/CBC modes -- it is the GCM nonce or the CBC IV,
   * and must be handed back on decrypt. */
  nonce?: string
  version: number
}

/** POST /vaults/{vault}/keys/{key_id}/encrypt. */
export async function encryptData(
  vaultName: string,
  keyId: string,
  input: EncryptInput
): Promise<EncryptResult> {
  const body = await request<{
    key_id: string
    algorithm: string
    value: string
    nonce?: string
    version: number
  }>(`${keyPath(vaultName, keyId)}/encrypt`, {
    method: "POST",
    body: JSON.stringify({
      value: input.value,
      algorithm: input.algorithm,
      version: input.version,
    }),
  })

  return {
    keyId: body.key_id,
    algorithm: body.algorithm,
    value: body.value,
    nonce: body.nonce,
    version: body.version,
  }
}

export interface DecryptInput {
  value: string
  algorithm: string
  nonce?: string
  version?: number
}

export interface DecryptResult {
  keyId: string
  algorithm: string
  value: string
  version: number
}

/** POST /vaults/{vault}/keys/{key_id}/decrypt. */
export async function decryptData(
  vaultName: string,
  keyId: string,
  input: DecryptInput
): Promise<DecryptResult> {
  const body = await request<{
    key_id: string
    algorithm: string
    value: string
    version: number
  }>(`${keyPath(vaultName, keyId)}/decrypt`, {
    method: "POST",
    body: JSON.stringify({
      value: input.value,
      nonce: input.nonce,
      algorithm: input.algorithm,
      version: input.version,
    }),
  })

  return {
    keyId: body.key_id,
    algorithm: body.algorithm,
    value: body.value,
    version: body.version,
  }
}

// --- Rotation policy -------------------------------------------------------

export interface KeyRotationPolicy {
  id: string
  keyId: string
  userId: string
  vaultId: string
  rotateAfterDays: number
  notifyBeforeExpiryDays: number
  expiryDays: number
  enabled: boolean
  lastRotatedAt?: string
  nextRotationAt?: string
  createdAt: string
  updatedAt: string
}

interface RotationPolicyBody {
  id: string
  key_id: string
  user_id: string
  vault_id: string
  rotate_after_days: number
  notify_before_expiry_days: number
  expiry_days: number
  enabled: boolean
  last_rotated_at?: string
  next_rotation_at?: string
  created_at: string
  updated_at: string
}

function mapRotationPolicy(body: RotationPolicyBody): KeyRotationPolicy {
  return {
    id: body.id,
    keyId: body.key_id,
    userId: body.user_id,
    vaultId: body.vault_id,
    rotateAfterDays: body.rotate_after_days,
    notifyBeforeExpiryDays: body.notify_before_expiry_days,
    expiryDays: body.expiry_days,
    enabled: body.enabled,
    lastRotatedAt: body.last_rotated_at,
    nextRotationAt: body.next_rotation_at,
    createdAt: body.created_at,
    updatedAt: body.updated_at,
  }
}

/** GET /vaults/{vault}/keys/{key_id}/rotationpolicy. Note the backend maps
 * BOTH "no such key" and "no policy set" to a 404 here, so a 404 is not
 * necessarily an error worth showing as one. */
export async function getRotationPolicy(
  vaultName: string,
  keyId: string
): Promise<KeyRotationPolicy> {
  return mapRotationPolicy(
    await request<RotationPolicyBody>(
      `${keyPath(vaultName, keyId)}/rotationpolicy`
    )
  )
}

export interface RotationPolicyInput {
  /** Must be at least 7 when `enabled` is true; a disabled policy accepts
   * any value, including 0. */
  rotateAfterDays: number
  notifyBeforeExpiryDays: number
  expiryDays: number
  enabled: boolean
}

/** PUT /vaults/{vault}/keys/{key_id}/rotationpolicy -- upsert. All four
 * fields are required: the backend struct has no pointers and no omitempty,
 * so a partial body silently zeroes the fields it leaves out. */
export async function setRotationPolicy(
  vaultName: string,
  keyId: string,
  policy: RotationPolicyInput
): Promise<KeyRotationPolicy> {
  return mapRotationPolicy(
    await request<RotationPolicyBody>(
      `${keyPath(vaultName, keyId)}/rotationpolicy`,
      {
        method: "PUT",
        body: JSON.stringify({
          rotate_after_days: policy.rotateAfterDays,
          notify_before_expiry_days: policy.notifyBeforeExpiryDays,
          expiry_days: policy.expiryDays,
          enabled: policy.enabled,
        }),
      }
    )
  )
}

/** DELETE /vaults/{vault}/keys/{key_id}/rotationpolicy. */
export async function clearRotationPolicy(
  vaultName: string,
  keyId: string
): Promise<void> {
  await request(`${keyPath(vaultName, keyId)}/rotationpolicy`, {
    method: "DELETE",
  })
}

// --- Backup and restore ----------------------------------------------------

/** POST /vaults/{vault}/keys/{key_id}/backup. The blob is a base64url-encoded
 * JSON envelope and is NOT encrypted -- the backend's own model/key.go says it
 * must be treated as key material. */
export async function backupKey(
  vaultName: string,
  keyId: string
): Promise<string> {
  const body = await request<{ blob: string }>(
    `${keyPath(vaultName, keyId)}/backup`,
    { method: "POST" }
  )
  return body.blob
}

/** POST /vaults/{vault}/keys/restore. */
export async function restoreKey(
  vaultName: string,
  blob: string
): Promise<void> {
  await request(`${keysPath(vaultName)}/restore`, {
    method: "POST",
    body: JSON.stringify({ blob }),
  })
}

// --- Soft-delete recovery --------------------------------------------------

export interface DeletedKey {
  id: string
  name: string
  type: string
  /** Present on the wire but nullable. */
  deletedAt?: string
  purgeProtection: boolean
}

function deletedKeysPath(vaultName: string): string {
  return `/vaults/${encodeURIComponent(vaultName)}/deleted/keys`
}

/** GET /vaults/{vault}/deleted/keys. */
export async function listDeletedKeys(
  vaultName: string
): Promise<DeletedKey[]> {
  const body = await request<{
    deleted_keys: {
      id: string
      name: string
      type: string
      deleted_at?: string | null
      purge_protection: boolean
    }[]
    total: number
  }>(deletedKeysPath(vaultName))

  return body.deleted_keys.map((key) => ({
    id: key.id,
    name: key.name,
    type: key.type,
    deletedAt: key.deleted_at ?? undefined,
    purgeProtection: key.purge_protection,
  }))
}

// There is deliberately no getDeletedKey() here. GET /deleted/keys/{key_id}
// is registered on the FLAT route only (api/soft_delete.go:400-401) -- the
// vault-scoped variant was never wired up -- so calling it would always
// resolve against the "default" vault and silently answer about the wrong
// vault's key, or 404. That is a real backend gap. The deleted-keys list
// already carries every field the single-item route returns (id, name, type,
// deleted_at, purge_protection), so nothing in the UI needs it.

/** POST /vaults/{vault}/deleted/keys/{key_id}/restore -- recovers a
 * soft-deleted key within the vault's retention window. */
export async function restoreDeletedKey(
  vaultName: string,
  keyId: string
): Promise<void> {
  await request(
    `${deletedKeysPath(vaultName)}/${encodeURIComponent(keyId)}/restore`,
    { method: "POST" }
  )
}

/** DELETE /vaults/{vault}/deleted/keys/{key_id}/purge -- permanent. Refused
 * with 403 when the key (or its vault) has purge protection enabled. */
export async function purgeKey(
  vaultName: string,
  keyId: string
): Promise<void> {
  await request(
    `${deletedKeysPath(vaultName)}/${encodeURIComponent(keyId)}/purge`,
    { method: "DELETE" }
  )
}
