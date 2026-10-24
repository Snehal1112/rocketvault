import type { ReactNode } from "react"

import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"

/**
 * The Card shell for one item in a resource-card grid: title + status on
 * one row, metadata below. Goes *inside* a `<Link className={
 * RESOURCE_CARD_LINK_CLASS}>` (card-grid.tsx) -- this component owns the
 * visual shell, the caller's Link owns the navigation and focus ring.
 */
export function ResourceCardShell({
  title,
  status,
  children,
}: {
  title: string
  status?: ReactNode
  children: ReactNode
}) {
  return (
    <Card
      size="sm"
      className="h-full gap-3 transition-shadow duration-150 group-hover:ring-foreground/15 dark:group-hover:ring-foreground/25"
    >
      <CardHeader className="flex flex-row items-center justify-between gap-3">
        <CardTitle className="truncate">{title}</CardTitle>
        {status}
      </CardHeader>
      <CardContent className="flex flex-col gap-1 text-xs text-muted-foreground">
        {children}
      </CardContent>
    </Card>
  )
}
