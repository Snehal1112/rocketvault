import type { Key } from "@/api/keys"
import { keyStatusOf } from "@/components/keys/key-summary"
import { StatusDot } from "@/components/status-dot"

/**
 * The dot-plus-word status every key surface renders, per the visual design
 * language doc's rule 2. The tone/label decision lives in key-summary.ts so
 * it can be tested without a DOM.
 */
export function KeyStatus({
  keyRecord,
  className,
}: {
  keyRecord: Key
  className?: string
}) {
  const status = keyStatusOf(keyRecord)
  return (
    <StatusDot tone={status.tone} label={status.label} className={className} />
  )
}
