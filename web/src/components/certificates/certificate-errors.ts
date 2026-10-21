import { ApiError } from "@/api/types"

/**
 * The verbatim message the backend sends when a certificate's own lifecycle
 * refuses the read (api/errors_certificate.go:20-21). Matched on rather than
 * on the status code, because it shares its 403 with a genuine role denial
 * and the two need opposite responses from the operator.
 */
const LIFECYCLE_MESSAGE = "disabled or outside its valid time window"

/**
 * True when a 403 is the certificate's own state, not the caller's role.
 *
 * This is not a hypothetical distinction: a disabled or expired certificate
 * still appears in the list but 403s on read, so the list -> detail
 * transition routinely produces a 403 that has nothing to do with
 * permissions. Telling a Certificates Officer they lack access, when in fact
 * they only need to re-enable the certificate, sends them to the wrong
 * person.
 */
export function isLifecycleDenial(error: unknown): boolean {
  return (
    error instanceof ApiError &&
    error.statusCode === 403 &&
    error.message.toLowerCase().includes(LIFECYCLE_MESSAGE)
  )
}
