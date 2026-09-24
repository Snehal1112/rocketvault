import type { RotationPolicyInput } from "@/api/keys"

/** The backend's own floor: internal/validation/key_validation.go rejects an
 * enabled policy that rotates more often than every 7 days. Checked here too
 * so the operator sees it before a round trip. */
const MIN_ROTATION_DAYS = 7

/**
 * Returns the first problem with a proposed schedule, or null when it is
 * acceptable. A DISABLED policy is stored but never acted on, so the backend
 * lets any value through -- including 0 -- and so does this.
 */
export function validateRotationPolicy(
  input: RotationPolicyInput
): string | null {
  const values = [
    input.rotateAfterDays,
    input.notifyBeforeExpiryDays,
    input.expiryDays,
  ]
  if (values.some((value) => Number.isNaN(value))) {
    return "Every interval must be a whole number of days."
  }
  if (input.notifyBeforeExpiryDays < 0 || input.expiryDays < 0) {
    return "Intervals cannot be negative."
  }
  if (input.enabled && input.rotateAfterDays < MIN_ROTATION_DAYS) {
    return "An enabled schedule must rotate at least 7 days apart."
  }
  return null
}
