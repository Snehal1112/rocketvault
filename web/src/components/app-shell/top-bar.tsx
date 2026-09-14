import { Fragment } from "react"
import { Link } from "@tanstack/react-router"

import type { BreadcrumbSegment } from "@/components/app-shell/breadcrumbs"
import {
  Breadcrumb,
  BreadcrumbItem,
  BreadcrumbLink,
  BreadcrumbList,
  BreadcrumbPage,
  BreadcrumbSeparator,
} from "@/components/ui/breadcrumb"
import { Separator } from "@/components/ui/separator"
import { SidebarTrigger } from "@/components/ui/sidebar"
import { cn } from "@/lib/utils"

/**
 * Renders the real path to the current page, not a static label. A
 * segment with a `link` is navigable; the last one never has one and
 * renders as the current page.
 */
export function TopBar({ segments }: { segments: BreadcrumbSegment[] }) {
  return (
    <header className="flex h-14 shrink-0 items-center gap-2 border-b px-4">
      <SidebarTrigger />
      <Separator orientation="vertical" className="mr-2 h-4" />
      <Breadcrumb>
        <BreadcrumbList>
          {segments.map((segment, index) => (
            // The trail up to this point is unique even when two crumbs
            // share a label, and it is stable across re-renders.
            <Fragment
              key={segments
                .slice(0, index + 1)
                .map((crumb) => crumb.label)
                .join("/")}
            >
              {index > 0 && <BreadcrumbSeparator />}
              <BreadcrumbItem>
                {segment.link ? (
                  <BreadcrumbLink
                    className={cn(segment.mono && "font-heading")}
                    render={<Link {...segment.link} />}
                  >
                    {segment.label}
                  </BreadcrumbLink>
                ) : (
                  <BreadcrumbPage
                    className={cn(segment.mono && "font-heading")}
                  >
                    {segment.label}
                  </BreadcrumbPage>
                )}
              </BreadcrumbItem>
            </Fragment>
          ))}
        </BreadcrumbList>
      </Breadcrumb>
    </header>
  )
}
