import type { ReactNode } from "react"
import { useLocation } from "@tanstack/react-router"

import { AccountMenu } from "@/components/app-shell/account-menu"
import { AdminNav } from "@/components/app-shell/admin-nav"
import { TopBar } from "@/components/app-shell/top-bar"
import { VaultNav } from "@/components/app-shell/vault-nav"
import { VaultSwitcher } from "@/components/app-shell/vault-switcher"
import { BrandLockup } from "@/components/landing/brand"
import { Badge } from "@/components/ui/badge"
import {
  Sidebar,
  SidebarContent,
  SidebarFooter,
  SidebarHeader,
  SidebarInset,
  SidebarProvider,
} from "@/components/ui/sidebar"
import { Toaster } from "@/components/ui/toast"

/**
 * One SidebarProvider mounted at the authenticated root; nav swaps between
 * vault-mode and admin-mode based on the active route -- no manual mode
 * toggle, the URL already encodes which mode is active (design doc §5).
 * TooltipProvider is already mounted globally in src/main.tsx, so it is
 * deliberately not re-mounted here; ToastProvider (via Toaster) and
 * SidebarProvider are not mounted anywhere else, so they are mounted here.
 */
export function AppShell({ children }: { children: ReactNode }) {
  const location = useLocation()
  const isAdminMode = location.pathname.startsWith("/admin")

  return (
    <SidebarProvider>
      <Toaster />
      <Sidebar>
        <SidebarHeader>
          <div className="flex items-center justify-between gap-2 px-2 py-1">
            <BrandLockup />
            {isAdminMode && <Badge variant="secondary">Admin</Badge>}
          </div>
          {!isAdminMode && <VaultSwitcher />}
        </SidebarHeader>
        <SidebarContent>
          {isAdminMode ? <AdminNav /> : <VaultNav />}
        </SidebarContent>
        <SidebarFooter>
          <AccountMenu />
        </SidebarFooter>
      </Sidebar>
      <SidebarInset>
        <TopBar title={isAdminMode ? "Admin" : "Vault"} />
        <div className="flex flex-1 flex-col gap-4 p-4">{children}</div>
      </SidebarInset>
    </SidebarProvider>
  )
}
