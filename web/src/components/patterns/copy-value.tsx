import { useState } from "react"
import { CheckIcon, CopyIcon } from "lucide-react"

import { Button } from "@/components/ui/button"
import { cn } from "@/lib/utils"

/**
 * A monospace value with a copy affordance -- used for key ids, JWK
 * components and crypto-operation output, all of which an operator copies far
 * more often than reads. The clipboard API is absent in some browsers and in
 * jsdom, so a failed write leaves the button in its idle state rather than
 * throwing.
 */
export function CopyValue({
  value,
  label,
  className,
}: {
  value: string
  label: string
  className?: string
}) {
  const [copied, setCopied] = useState(false)

  async function handleCopy() {
    try {
      await navigator.clipboard.writeText(value)
      setCopied(true)
      setTimeout(() => setCopied(false), 1500)
    } catch {
      // No clipboard permission (or no clipboard at all) -- the value is
      // still selectable by hand, so there is nothing useful to report.
    }
  }

  return (
    <div className={cn("flex items-start gap-2", className)}>
      <code className="min-w-0 flex-1 overflow-x-auto rounded-2xl bg-muted/60 px-3 py-2 font-heading text-xs break-all">
        {value}
      </code>
      <Button
        type="button"
        variant="ghost"
        size="icon"
        aria-label={`Copy ${label}`}
        onClick={handleCopy}
      >
        {copied ? <CheckIcon /> : <CopyIcon />}
      </Button>
    </div>
  )
}
