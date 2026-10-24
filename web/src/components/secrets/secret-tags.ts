// A secret's tags are a flat []string on the wire (model/secret.go:188-198),
// not the key=value map a vault carries -- so "env=prod" is just a string
// the operator chose, and this module never tries to split on "=".

/** Backend limit: at most 15 tags (internal/validation/secret_validation.go). */
export const MAX_SECRET_TAGS = 15

/** Backend limit: each tag is 1-256 characters. */
export const MAX_SECRET_TAG_LENGTH = 256

/**
 * Parses a comma-separated tag input into the wire list. Blank input yields
 * undefined -- the caller then omits `tags` entirely rather than sending an
 * empty array, which the backend would read as "replace all tags with none".
 */
export function parseTagList(raw: string): string[] | undefined {
  const entries = raw
    .split(",")
    .map((tag) => tag.trim())
    .filter(Boolean)

  if (entries.length === 0) {
    return undefined
  }
  return [...new Set(entries)]
}

/** The inverse of parseTagList, for pre-filling an edit form. */
export function formatTagList(tags: string[] | undefined): string {
  return (tags ?? []).join(", ")
}

/** Returns a human-readable reason the list would be rejected, or null. */
export function validateTagList(tags: string[] | undefined): string | null {
  if (!tags) {
    return null
  }
  if (tags.length > MAX_SECRET_TAGS) {
    return `A secret can carry at most ${MAX_SECRET_TAGS} tags.`
  }
  if (tags.some((tag) => tag.length > MAX_SECRET_TAG_LENGTH)) {
    return `Each tag must be ${MAX_SECRET_TAG_LENGTH} characters or fewer.`
  }
  return null
}
