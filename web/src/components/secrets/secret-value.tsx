import { useEffect, useState } from "react"
import { CheckIcon, CopyIcon, EyeIcon, EyeOffIcon } from "lucide-react"

import { Button } from "@/components/ui/button"
import { Spinner } from "@/components/ui/spinner"

// A fixed-width mask, deliberately not `"•".repeat(value.length)` -- the
// length of a credential is information, and a masked field that visibly
// grows with the secret leaks it to anyone looking at the screen.
const MASK = "••••••••"

/**
 * Renders a secret value masked until the operator asks for it. Masked is
 * the initial state unconditionally: a secrets manager must never flash a
 * value on render, including for the split second before an effect runs.
 *
 * Copy deliberately does not reveal -- pasting a value into a terminal is
 * the common case, and it should not require putting the value on screen.
 */
export function SecretValue({
  value,
  isLoading = false,
  onReveal,
  label = "Reveal",
}: {
  value?: string
  isLoading?: boolean
  /** Called the first time the operator reveals, for a lazily-fetched
   * value. Omit when the value is already in hand. */
  onReveal?: () => void
  label?: string
}) {
  const [revealed, setRevealed] = useState(false)
  const [copied, setCopied] = useState(false)

  // Re-mask whenever the underlying value changes -- switching to another
  // version while revealed must not carry the revealed state over. Done by
  // adjusting state during render (React's documented pattern for "reset
  // state when a prop changes") rather than in an effect, so there is no
  // frame in which the new value is on screen while still marked revealed.
  const [renderedValue, setRenderedValue] = useState(value)
  if (value !== renderedValue) {
    setRenderedValue(value)
    setRevealed(false)
  }

  useEffect(() => {
    if (!copied) {
      return
    }
    const timer = setTimeout(() => setCopied(false), 2000)
    return () => clearTimeout(timer)
  }, [copied])

  function handleToggle() {
    if (!revealed && onReveal) {
      onReveal()
    }
    setRevealed((current) => !current)
  }

  async function handleCopy() {
    if (value === undefined) {
      return
    }
    try {
      await navigator.clipboard.writeText(value)
      setCopied(true)
    } catch {
      // Clipboard access can be denied (insecure origin, or the user said
      // no). Silently leaving the button un-ticked is the honest outcome;
      // the value is still revealable and selectable by hand.
    }
  }

  const showValue = revealed && value !== undefined

  return (
    <div className="flex flex-wrap items-center gap-2">
      <output
        aria-label="Secret value"
        className="min-w-0 flex-1 overflow-x-auto rounded-3xl bg-muted/60 px-4 py-2.5 font-heading text-sm break-all whitespace-pre-wrap"
      >
        {isLoading && revealed ? (
          <Spinner className="size-4" />
        ) : showValue ? (
          value
        ) : (
          MASK
        )}
      </output>
      <div className="flex items-center gap-2">
        <Button
          type="button"
          variant="outline"
          size="sm"
          onClick={handleToggle}
        >
          {revealed ? <EyeOffIcon /> : <EyeIcon />}
          {revealed ? "Hide" : label}
        </Button>
        <Button
          type="button"
          variant="outline"
          size="sm"
          onClick={handleCopy}
          disabled={value === undefined}
        >
          {copied ? <CheckIcon /> : <CopyIcon />}
          {copied ? "Copied" : "Copy"}
        </Button>
      </div>
    </div>
  )
}
