import type { ComponentProps } from "react"

import { cn } from "@/lib/utils"

/**
 * Responsive grid for a list of resource cards (design language doc's
 * card-grid rule) -- one column on mobile, two at sm, three at lg. Shared by
 * vaults/secrets/keys list screens instead of the identical div repeated in
 * each.
 */
export function CardGrid({ className, ...props }: ComponentProps<"div">) {
  return (
    <div
      {...props}
      className={cn(
        "grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-3",
        className
      )}
    />
  )
}
