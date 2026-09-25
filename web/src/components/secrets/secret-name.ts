// Mirrors the backend's own name rule so the operator gets the reason
// inline instead of a 400 after a round trip. Source of truth:
// internal/validation/common.go:13 (`^[a-zA-Z][a-zA-Z0-9-]{0,126}$`) and
// internal/validation/secret_validation.go:35-54 (1-127 characters).

const SECRET_NAME_PATTERN = /^[a-zA-Z][a-zA-Z0-9-]{0,126}$/

export const MAX_SECRET_NAME_LENGTH = 127

/** Returns a human-readable reason the name would be rejected, or null. */
export function validateSecretName(name: string): string | null {
  const trimmed = name.trim()
  if (!trimmed) {
    return "Name is required."
  }
  if (trimmed.length > MAX_SECRET_NAME_LENGTH) {
    return `Name must be ${MAX_SECRET_NAME_LENGTH} characters or fewer.`
  }
  if (!SECRET_NAME_PATTERN.test(trimmed)) {
    return "Name must start with a letter and use only letters, numbers, and hyphens."
  }
  return null
}
