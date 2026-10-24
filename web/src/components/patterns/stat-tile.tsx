import type { ComponentProps } from "react"

import { Card, CardContent } from "@/components/ui/card"
import { cn } from "@/lib/utils"

/**
 * One number+label tile for a resource list's summary row (design language
 * doc's stat-row rule: big font-heading numeral, small muted label). Shared
 * across vaults/secrets/keys list screens rather than redefined per file --
 * see StatGrid below for why this extraction happened when it did.
 */
export function StatTile({
  value,
  label,
}: {
  value: number | string
  label: string
}) {
  return (
    <Card size="sm" className="gap-0">
      <CardContent>
        <p className="font-heading text-2xl leading-none font-medium tabular-nums">
          {value}
        </p>
        <p className="mt-1.5 text-xs text-muted-foreground">{label}</p>
      </CardContent>
    </Card>
  )
}

/**
 * Responsive grid container for a row of StatTiles. Defaults to three
 * columns (vaults, secrets); pass a `grid-cols-*`/`lg:grid-cols-*`
 * className to override the count for a different tile count (keys' four).
 * `cn()`'s tailwind-merge pass drops the default in favor of an overridden
 * column count rather than combining both.
 */
export function StatGrid({ className, ...props }: ComponentProps<"section">) {
  return (
    <section
      {...props}
      className={cn("grid grid-cols-3 gap-3 sm:gap-4", className)}
    />
  )
}
