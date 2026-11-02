import type { Certificate } from "@/api/certificates"
import { certificateStatusOf } from "@/components/certificates/certificate-status"
import { StatusDot } from "@/components/status-dot"

/**
 * The dot-plus-word status every certificate surface renders, per the visual
 * design language doc's rule 2. The tone/label decision lives in
 * certificate-status.ts so it can be tested without a DOM.
 *
 * This is the first screen to use StatusDot's `warning` and `danger` tones:
 * an expiry is the one certificate attribute where "fine", "act soon" and
 * "already broken" are three genuinely different states, and collapsing them
 * into enabled/disabled would hide the only one that costs an outage.
 */
export function CertificateStatusDot({
  certificate,
  className,
}: {
  certificate: Certificate
  className?: string
}) {
  const status = certificateStatusOf(certificate)
  return (
    <StatusDot tone={status.tone} label={status.label} className={className} />
  )
}
