import type { ReactNode } from "react"

import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card"

/**
 * The red-bordered card shell every destructive-actions section uses
 * (design language doc: a danger zone should look different at a glance,
 * not just have a red button at the bottom of a normal-looking form).
 * `description` is the card-level summary; each action inside is a
 * `DangerAction` below.
 */
export function DangerZoneCard({
  description,
  children,
}: {
  description: ReactNode
  children: ReactNode
}) {
  return (
    <Card className="border border-destructive/30 ring-destructive/10 dark:ring-destructive/20">
      <CardHeader>
        <CardTitle className="text-destructive">Danger zone</CardTitle>
        <CardDescription>{description}</CardDescription>
      </CardHeader>
      <CardContent className="flex flex-col gap-5">{children}</CardContent>
    </Card>
  )
}

/** One labelled destructive action inside a DangerZoneCard: consequence
 * copy on the left, the trigger (an AlertDialog, typically) on the right. */
export function DangerAction({
  title,
  description,
  error,
  children,
}: {
  title: string
  description: ReactNode
  error: string | null
  children: ReactNode
}) {
  return (
    <div className="flex flex-col gap-3">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="max-w-[60ch]">
          <h3 className="font-heading text-sm font-medium">{title}</h3>
          <p className="mt-1 text-sm text-muted-foreground">{description}</p>
        </div>
        {children}
      </div>
      {error && (
        <p role="alert" className="text-sm text-destructive">
          {error}
        </p>
      )}
    </div>
  )
}
