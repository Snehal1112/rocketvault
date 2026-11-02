// The keys API takes and returns STANDARD base64 with padding for every
// crypto-operation payload (api/request.go's b64Field uses
// base64.StdEncoding). These helpers exist so the playground can accept plain
// text from an operator who is testing a key, without making them run the
// value through a separate tool first.

/** Encodes text as standard, padded base64, UTF-8 safe -- btoa alone throws
 * on any code point above U+00FF. */
export function encodeUtf8Base64(text: string): string {
  const bytes = new TextEncoder().encode(text)
  let binary = ""
  for (const byte of bytes) {
    binary += String.fromCharCode(byte)
  }
  return btoa(binary)
}

/** Decodes standard base64 back to text, or null when the input is not valid
 * base64 or not valid UTF-8 -- binary output (a signature, a wrapped key) is
 * expected to fail here, and the caller shows the base64 instead. */
export function decodeUtf8Base64(value: string): string | null {
  try {
    const binary = atob(value)
    const bytes = Uint8Array.from(binary, (char) => char.charCodeAt(0))
    return new TextDecoder("utf-8", { fatal: true }).decode(bytes)
  } catch {
    return null
  }
}

const BASE64_PATTERN = /^[A-Za-z0-9+/]*={0,2}$/

/** A cheap client-side check so an obviously-wrong paste is caught before a
 * round trip. The server does the authoritative validation. */
export function looksLikeBase64(value: string): boolean {
  const trimmed = value.trim()
  return (
    trimmed.length > 0 &&
    trimmed.length % 4 === 0 &&
    BASE64_PATTERN.test(trimmed)
  )
}
