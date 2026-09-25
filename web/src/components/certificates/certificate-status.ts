import type { Certificate } from "@/api/certificates"

const DAY = 24 * 60 * 60 * 1000

/** What the backend uses when a certificate carries no renewal_days of its
 * own (api/certificates.go's "defaults to 30"). Mirrored here so the warning
 * window matches the one the renewal scheduler would actually act on. */
const DEFAULT_RENEWAL_DAYS = 30

export interface CertificateStatus {
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
 * The single status a certificate card or row shows, worst-first.
 *
 * The "expiring soon" threshold is the certificate's OWN `renewal_days`, not
 * a fixed constant: that is the field the renewal scheduler reads
 * (internal/services/certificates/certificate_service.go:128-134), so warning
 * on any other window would mean the dashboard and the scheduler disagreed
 * about which certificates are due. The label states the remaining days
 * rather than a bare "Expiring soon", because the operator's next question is
 * always "how long have I got".
 */
export function certificateStatusOf(
  certificate: Certificate,
  now: Date = new Date()
): CertificateStatus {
  if (!certificate.enabled) {
    return { tone: "off", label: "Disabled" }
  }

  const current = now.getTime()
  const expiresAt = parse(certificate.expiresAt)

  if (expiresAt !== null) {
    if (expiresAt <= current) {
      return { tone: "danger", label: "Expired" }
    }

    const window =
      certificate.renewalDays > 0
        ? certificate.renewalDays
        : DEFAULT_RENEWAL_DAYS
    const remaining = expiresAt - current
    if (remaining <= window * DAY) {
      // Rounded up, so a certificate with eight hours left reads "in 1 day"
      // rather than "in 0 days".
      const remainingDays = Math.ceil(remaining / DAY)
      return {
        tone: "warning",
        label: `Expires in ${remainingDays} ${
          remainingDays === 1 ? "day" : "days"
        }`,
      }
    }
  }

  const notBefore = parse(certificate.notBefore)
  if (notBefore !== null && notBefore > current) {
    return { tone: "warning", label: "Not yet valid" }
  }

  return { tone: "on", label: "Valid" }
}

export interface CertificatesSummary {
  total: number
  expiringSoon: number
  expired: number
}

/**
 * Counts for the stat row above the certificate grid (visual design language
 * doc, rule 3). These three are the ones worth summarizing for certificates:
 * an expiry an operator misses is an outage, which is not true of any other
 * attribute on the list payload.
 */
export function summarizeCertificates(
  certificates: Certificate[],
  now: Date = new Date()
): CertificatesSummary {
  let expiringSoon = 0
  let expired = 0

  for (const certificate of certificates) {
    const status = certificateStatusOf(certificate, now)
    if (status.tone === "warning" && status.label.startsWith("Expires in")) {
      expiringSoon += 1
    }
    if (status.tone === "danger") {
      expired += 1
    }
  }

  return { total: certificates.length, expiringSoon, expired }
}
