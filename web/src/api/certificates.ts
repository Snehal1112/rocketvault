import { request } from "@/api/client"
import { ApiError } from "@/api/types"

// Route shapes verified directly against the Go backend (../../../api/
// certificates.go, certificate_policy.go, soft_delete.go, backup_item.go,
// errors_certificate.go) -- not guessed. Notes that shaped this module:
//
//   * Every certificate route is registered twice: flat (/certificates/...)
//     and vault-scoped (/vaults/{vault_name}/certificates/...). The flat form
//     silently resolves to the "default" vault, so this module always uses the
//     vault-scoped form.
//   * Certificates are addressed by UUID only -- the path var regex is
//     `certificate_id:[A-Fa-f0-9-]+` and there is no name lookup anywhere.
//   * NO response in this API carries the certificate PEM or its private key.
//     model.Certificate stores both, but CertificateResponse projects neither,
//     and there is no download route. The mappers below copy an explicit
//     allow-list of fields so that a backend which ever started emitting them
//     still could not leak them into the UI.
//   * There is NO HTTP renew endpoint. `rocketvault certificate renew <id>`
//     calls the service directly; no route registers it. Hence no
//     renewCertificate() here -- see the renewal card's copy for what the UI
//     tells the operator instead.

interface CertificateResponseBody {
  id: string
  name: string
  user_id: string
  created_at: string
  // No omitempty on the Go side and the slice is nilable, so this really can
  // arrive as null rather than [].
  tags: string[] | null
  auto_renew: boolean
  renewal_days: number
  expires_at?: string
  enabled: boolean
  not_before?: string
}

/** One certificate as the dashboard sees it -- metadata only, by design. */
export interface Certificate {
  id: string
  name: string
  userId: string
  createdAt: string
  tags: string[]
  autoRenew: boolean
  renewalDays: number
  expiresAt?: string
  enabled: boolean
  notBefore?: string
}

function mapCertificate(body: CertificateResponseBody): Certificate {
  return {
    id: body.id,
    name: body.name,
    userId: body.user_id,
    createdAt: body.created_at,
    tags: body.tags ?? [],
    autoRenew: body.auto_renew,
    renewalDays: body.renewal_days,
    expiresAt: body.expires_at,
    enabled: body.enabled,
    notBefore: body.not_before,
  }
}

function certificatesPath(vaultName: string): string {
  return `/vaults/${encodeURIComponent(vaultName)}/certificates`
}

function certificatePath(vaultName: string, certificateId: string): string {
  return `${certificatesPath(vaultName)}/${encodeURIComponent(certificateId)}`
}

/** GET /vaults/{vault}/certificates. */
export async function listCertificates(
  vaultName: string
): Promise<Certificate[]> {
  const body = await request<{ certificates: CertificateResponseBody[] }>(
    certificatesPath(vaultName)
  )
  return body.certificates.map(mapCertificate)
}

/**
 * GET /vaults/{vault}/certificates/{certificate_id}.
 *
 * A disabled or expired certificate still appears in the list but answers 403
 * here ("certificate is disabled or outside its valid time window"). That is a
 * lifecycle state, not a role denial -- callers must distinguish the two.
 */
export async function getCertificate(
  vaultName: string,
  certificateId: string
): Promise<Certificate> {
  return mapCertificate(
    await request<CertificateResponseBody>(
      certificatePath(vaultName, certificateId)
    )
  )
}

export interface CreateCertificateInput {
  name: string
  /** UUID of an existing key in the SAME vault. Required -- the service
   * refuses to issue against a key it cannot read. */
  keyId: string
  /** Must be positive; the handler 400s on zero or negative. */
  validityDays: number
  tags?: string[]
  autoRenew?: boolean
  /** Days before expiry to renew; the backend defaults to 30. */
  renewalDays?: number
  /** UUID of an existing certificate to sign with. Its presence is what
   * selects the CA-signed path; omitting it issues self-signed. There is
   * deliberately no ca_key_id counterpart -- the backend field exists but is
   * explicitly unused. */
  caCertId?: string
  isCa?: boolean
  enabled?: boolean
  notBefore?: string
  purgeProtection?: boolean
}

/** POST /vaults/{vault}/certificates -- 201 on success. */
export async function createCertificate(
  vaultName: string,
  input: CreateCertificateInput
): Promise<Certificate> {
  const body: Record<string, unknown> = {
    name: input.name,
    key_id: input.keyId,
    validity_days: input.validityDays,
  }
  if (input.tags !== undefined) {
    body.tags = input.tags
  }
  if (input.autoRenew !== undefined) {
    body.auto_renew = input.autoRenew
  }
  if (input.renewalDays !== undefined) {
    body.renewal_days = input.renewalDays
  }
  if (input.caCertId !== undefined) {
    body.ca_cert_id = input.caCertId
  }
  if (input.isCa !== undefined) {
    body.is_ca = input.isCa
  }
  if (input.enabled !== undefined) {
    body.enabled = input.enabled
  }
  if (input.notBefore !== undefined) {
    body.not_before = input.notBefore
  }
  if (input.purgeProtection !== undefined) {
    body.purge_protection = input.purgeProtection
  }

  return mapCertificate(
    await request<CertificateResponseBody>(certificatesPath(vaultName), {
      method: "POST",
      body: JSON.stringify(body),
    })
  )
}

/** The fields PUT accepts. `key_id` and `ca_cert_id` are absent on purpose:
 * both are fixed at issuance and the update request carries neither. */
export interface UpdateCertificateInput {
  name?: string
  tags?: string[]
  autoRenew?: boolean
  renewalDays?: number
  enabled?: boolean
  notBefore?: string
  purgeProtection?: boolean
}

/**
 * PUT /vaults/{vault}/certificates/{certificate_id}.
 *
 * Only explicitly-passed fields are sent. A body with every field unset is a
 * 400 server-side, so a naive "send the whole form" implementation would turn
 * a no-op save into a confusing server error -- and would also overwrite
 * fields the operator never touched.
 */
export async function updateCertificate(
  vaultName: string,
  certificateId: string,
  patch: UpdateCertificateInput
): Promise<Certificate> {
  const body: Record<string, unknown> = {}
  if (patch.name !== undefined) {
    body.name = patch.name
  }
  if (patch.tags !== undefined) {
    body.tags = patch.tags
  }
  if (patch.autoRenew !== undefined) {
    body.auto_renew = patch.autoRenew
  }
  if (patch.renewalDays !== undefined) {
    body.renewal_days = patch.renewalDays
  }
  if (patch.enabled !== undefined) {
    body.enabled = patch.enabled
  }
  if (patch.notBefore !== undefined) {
    body.not_before = patch.notBefore
  }
  if (patch.purgeProtection !== undefined) {
    body.purge_protection = patch.purgeProtection
  }

  return mapCertificate(
    await request<CertificateResponseBody>(
      certificatePath(vaultName, certificateId),
      { method: "PUT", body: JSON.stringify(body) }
    )
  )
}

/** DELETE /vaults/{vault}/certificates/{certificate_id} -- soft-delete. */
export async function deleteCertificate(
  vaultName: string,
  certificateId: string
): Promise<void> {
  await request(certificatePath(vaultName, certificateId), {
    method: "DELETE",
  })
}

// --- Certificate policy ----------------------------------------------------

interface CertificatePolicyBody {
  id: string
  certificate_id: string
  user_id: string
  validity_months: number
  key_type: string
  key_size?: number
  curve?: string
  subject: string
  sans?: string
  auto_renew: boolean
  days_before_expiry: number
  issuer_name?: string
  created_at: string
  updated_at: string
}

export interface CertificatePolicy {
  id: string
  certificateId: string
  userId: string
  validityMonths: number
  keyType: string
  keySize?: number
  curve?: string
  subject: string
  /** A comma-separated string on the wire, NOT an array -- model.
   * CertificatePolicy declares SANs as a plain string. */
  sans?: string
  autoRenew: boolean
  daysBeforeExpiry: number
  issuerName?: string
  createdAt: string
  updatedAt: string
}

function mapPolicy(body: CertificatePolicyBody): CertificatePolicy {
  return {
    id: body.id,
    certificateId: body.certificate_id,
    userId: body.user_id,
    validityMonths: body.validity_months,
    keyType: body.key_type,
    keySize: body.key_size,
    curve: body.curve,
    subject: body.subject,
    sans: body.sans,
    autoRenew: body.auto_renew,
    daysBeforeExpiry: body.days_before_expiry,
    issuerName: body.issuer_name,
    createdAt: body.created_at,
    updatedAt: body.updated_at,
  }
}

function policyPath(vaultName: string, certificateId: string): string {
  return `${certificatePath(vaultName, certificateId)}/policy`
}

/**
 * GET /vaults/{vault}/certificates/{certificate_id}/policy, or null when no
 * policy is set.
 *
 * The backend answers 404 for BOTH "no such certificate" and "no policy on
 * this certificate", so a 404 cannot be shown as an error: the overwhelmingly
 * common case is a certificate that simply has no policy yet, which the UI
 * renders as an empty state. A caller that has already read the certificate
 * knows it exists, so the ambiguity costs nothing.
 */
export async function getCertificatePolicy(
  vaultName: string,
  certificateId: string
): Promise<CertificatePolicy | null> {
  try {
    return mapPolicy(
      await request<CertificatePolicyBody>(policyPath(vaultName, certificateId))
    )
  } catch (error) {
    if (error instanceof ApiError && error.statusCode === 404) {
      return null
    }
    throw error
  }
}

/** The upsert body. Every field is sent: the Go struct has no pointers and no
 * omitempty on the required ones, so a partial body zeroes what it omits. */
export interface CertificatePolicyInput {
  validityMonths: number
  keyType: string
  keySize?: number
  curve?: string
  subject: string
  sans?: string
  autoRenew: boolean
  daysBeforeExpiry: number
  issuerName?: string
}

/** PUT /vaults/{vault}/certificates/{certificate_id}/policy -- upsert, 200. */
export async function upsertCertificatePolicy(
  vaultName: string,
  certificateId: string,
  policy: CertificatePolicyInput
): Promise<CertificatePolicy> {
  const body: Record<string, unknown> = {
    validity_months: policy.validityMonths,
    key_type: policy.keyType,
    subject: policy.subject,
    auto_renew: policy.autoRenew,
    days_before_expiry: policy.daysBeforeExpiry,
  }
  if (policy.keySize !== undefined) {
    body.key_size = policy.keySize
  }
  if (policy.curve !== undefined) {
    body.curve = policy.curve
  }
  if (policy.sans !== undefined) {
    body.sans = policy.sans
  }
  if (policy.issuerName !== undefined) {
    body.issuer_name = policy.issuerName
  }

  return mapPolicy(
    await request<CertificatePolicyBody>(policyPath(vaultName, certificateId), {
      method: "PUT",
      body: JSON.stringify(body),
    })
  )
}

/** DELETE /vaults/{vault}/certificates/{certificate_id}/policy. */
export async function deleteCertificatePolicy(
  vaultName: string,
  certificateId: string
): Promise<void> {
  await request(policyPath(vaultName, certificateId), { method: "DELETE" })
}

// --- Backup and restore ----------------------------------------------------

/** POST /vaults/{vault}/certificates/{certificate_id}/backup. The blob is an
 * opaque envelope, NOT a PEM -- it is only useful as input to restore. */
export async function backupCertificate(
  vaultName: string,
  certificateId: string
): Promise<string> {
  const body = await request<{ blob: string }>(
    `${certificatePath(vaultName, certificateId)}/backup`,
    { method: "POST" }
  )
  return body.blob
}

/** POST /vaults/{vault}/certificates/restore. A blob the backend cannot
 * decode comes back as a 400 on "blob". */
export async function restoreCertificate(
  vaultName: string,
  blob: string
): Promise<void> {
  await request(`${certificatesPath(vaultName)}/restore`, {
    method: "POST",
    body: JSON.stringify({ blob }),
  })
}

// --- Soft-delete recovery --------------------------------------------------

/** The deleted-certificates row carries exactly these four fields -- note it
 * has no created_at, unlike the deleted-secrets row. There is also no GET for
 * a single deleted certificate (keys have one; certificates and secrets
 * deliberately do not), so this list is the only source. */
export interface DeletedCertificate {
  id: string
  name: string
  /** Present on the wire but nullable. */
  deletedAt?: string
  purgeProtection: boolean
}

function deletedCertificatesPath(vaultName: string): string {
  return `/vaults/${encodeURIComponent(vaultName)}/deleted/certificates`
}

/** GET /vaults/{vault}/deleted/certificates. */
export async function listDeletedCertificates(
  vaultName: string
): Promise<DeletedCertificate[]> {
  const body = await request<{
    deleted_certificates: {
      id: string
      name: string
      deleted_at?: string | null
      purge_protection: boolean
    }[]
    total: number
  }>(deletedCertificatesPath(vaultName))

  return body.deleted_certificates.map((item) => ({
    id: item.id,
    name: item.name,
    deletedAt: item.deleted_at ?? undefined,
    purgeProtection: item.purge_protection,
  }))
}

export interface RecoveredCertificate {
  id: string
  /** The server's own wording ("Certificate recovered successfully"), shown
   * verbatim rather than restated client-side. */
  message: string
}

/** POST /vaults/{vault}/deleted/certificates/{certificate_id}/restore. */
export async function recoverCertificate(
  vaultName: string,
  certificateId: string
): Promise<RecoveredCertificate> {
  const body = await request<{ id: string; message: string }>(
    `${deletedCertificatesPath(vaultName)}/${encodeURIComponent(
      certificateId
    )}/restore`,
    { method: "POST" }
  )
  return { id: body.id, message: body.message }
}

/**
 * DELETE /vaults/{vault}/deleted/certificates/{certificate_id}/purge --
 * permanent.
 *
 * Refused with 403 when ANY of three independent protections is on: the
 * certificate's own purge_protection, its vault's, or the instance-wide
 * soft_delete.purge_protection. Only the first is visible to the client, so
 * callers must not pre-block on it -- let the server decide and surface its
 * message.
 */
export async function purgeCertificate(
  vaultName: string,
  certificateId: string
): Promise<void> {
  await request(
    `${deletedCertificatesPath(vaultName)}/${encodeURIComponent(
      certificateId
    )}/purge`,
    { method: "DELETE" }
  )
}
