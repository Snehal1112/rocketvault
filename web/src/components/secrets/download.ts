/**
 * Hands a blob to the browser as a file download. Kept in this module
 * rather than a shared lib because it exists purely for the two secrets
 * screens that produce files (export, and a single-secret backup).
 *
 * The object URL is revoked on the next tick rather than immediately --
 * Safari cancels an in-flight download if the URL is revoked in the same
 * task that clicked the link.
 */
export function downloadBlob(blob: Blob, filename: string): void {
  const url = URL.createObjectURL(blob)
  const anchor = document.createElement("a")
  anchor.href = url
  anchor.download = filename
  document.body.appendChild(anchor)
  anchor.click()
  anchor.remove()
  setTimeout(() => URL.revokeObjectURL(url), 0)
}

/** Downloads a string as a file, for text the UI already holds in memory. */
export function downloadText(
  text: string,
  filename: string,
  type = "application/json"
): void {
  downloadBlob(new Blob([text], { type }), filename)
}
