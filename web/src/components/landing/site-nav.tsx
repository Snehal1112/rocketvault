import { useState } from "react"
import { Link } from "@tanstack/react-router"
import { Menu } from "lucide-react"

import { Button } from "@/components/ui/button"
import {
  Sheet,
  SheetContent,
  SheetHeader,
  SheetTitle,
  SheetTrigger,
} from "@/components/ui/sheet"
import {
  BrandIcon,
  Wordmark as BrandWordmark,
  GitHubMark,
} from "@/components/landing/brand"
import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@/components/ui/tooltip"
import { REPO_URL, SECTIONS } from "@/components/landing/content"

function Wordmark() {
  return (
    <a href="#top" className="flex items-center gap-2">
      <BrandIcon className="size-6" />
      <BrandWordmark />
    </a>
  )
}

export function SiteNav() {
  const [open, setOpen] = useState(false)

  return (
    <header className="sticky top-0 z-50 border-b border-border bg-background/80 backdrop-blur-sm">
      <nav className="mx-auto flex h-14 w-full max-w-6xl items-center gap-8 px-6">
        <Wordmark />

        <ul className="hidden items-center gap-6 md:flex">
          {SECTIONS.map((section) => (
            <li key={section.href}>
              <a
                href={section.href}
                className="text-sm text-muted-foreground transition-colors hover:text-foreground"
              >
                {section.label}
              </a>
            </li>
          ))}
        </ul>

        <div className="ml-auto flex items-center gap-2">
          <Tooltip>
            <TooltipTrigger
              render={
                <Button
                  render={
                    <a href={REPO_URL} aria-label="RocketVault on GitHub" />
                  }
                  variant="ghost"
                  size="icon"
                  className="hidden sm:inline-flex"
                />
              }
            >
              <GitHubMark className="size-[1.05rem]" />
            </TooltipTrigger>
            <TooltipContent>View the source on GitHub</TooltipContent>
          </Tooltip>

          <Button
            render={<Link to="/login" />}
            variant="outline"
            size="sm"
            className="hidden sm:inline-flex"
          >
            Sign in
          </Button>

          <Sheet open={open} onOpenChange={setOpen}>
            <SheetTrigger
              render={
                <Button variant="ghost" size="icon" className="md:hidden" />
              }
            >
              <Menu aria-hidden="true" />
              <span className="sr-only">Open menu</span>
            </SheetTrigger>
            <SheetContent side="right" className="w-64">
              <SheetHeader>
                <SheetTitle className="font-heading text-sm">
                  Navigation
                </SheetTitle>
              </SheetHeader>
              <ul className="flex flex-col gap-1 px-4">
                {SECTIONS.map((section) => (
                  <li key={section.href}>
                    <a
                      href={section.href}
                      onClick={() => setOpen(false)}
                      className="block rounded-md px-2 py-2 text-sm text-muted-foreground transition-colors hover:bg-muted hover:text-foreground"
                    >
                      {section.label}
                    </a>
                  </li>
                ))}
                <li>
                  <a
                    href={REPO_URL}
                    className="flex items-center gap-2 rounded-md px-2 py-2 text-sm text-muted-foreground transition-colors hover:bg-muted hover:text-foreground"
                  >
                    <GitHubMark />
                    GitHub
                  </a>
                </li>
                <li>
                  <Link
                    to="/login"
                    onClick={() => setOpen(false)}
                    className="block rounded-md px-2 py-2 text-sm font-medium text-foreground transition-colors hover:bg-muted"
                  >
                    Sign in
                  </Link>
                </li>
              </ul>
            </SheetContent>
          </Sheet>
        </div>
      </nav>
    </header>
  )
}
