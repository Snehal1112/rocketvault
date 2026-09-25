import { cva, type VariantProps } from "class-variance-authority"

import { cn } from "@/lib/utils"

/**
 * The dashboard-wide status convention (visual design language doc, rule
 * 2): a colored dot plus a word, never a bare badge. Reads like a process
 * list, which is what an operator scanning a resource list is doing.
 * "on" is a filled dot; "off" is a hollow ring, so the two are
 * distinguishable without relying on color alone.
 */
const statusDotVariants = cva("size-2 shrink-0 rounded-full", {
  variants: {
    tone: {
      on: "bg-success",
      off: "border border-muted-foreground/70",
      warning: "bg-warning",
      danger: "bg-destructive",
    },
  },
  defaultVariants: { tone: "off" },
})

export function StatusDot({
  tone,
  label,
  className,
}: VariantProps<typeof statusDotVariants> & {
  label: string
  className?: string
}) {
  return (
    <span
      data-slot="status-dot"
      className={cn(
        "inline-flex items-center gap-1.5 font-heading text-xs whitespace-nowrap",
        tone === "on" && "text-foreground",
        tone !== "on" && "text-muted-foreground",
        className
      )}
    >
      <span aria-hidden="true" className={statusDotVariants({ tone })} />
      {label}
    </span>
  )
}

/** The enabled/disabled pair every vault-shaped surface renders. */
export function VaultStatus({
  enabled,
  className,
}: {
  enabled: boolean
  className?: string
}) {
  return (
    <StatusDot
      tone={enabled ? "on" : "off"}
      label={enabled ? "Enabled" : "Disabled"}
      className={className}
    />
  )
}
