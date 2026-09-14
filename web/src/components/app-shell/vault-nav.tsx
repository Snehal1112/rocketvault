import { Link, useParams } from "@tanstack/react-router"
import { KeyRoundIcon } from "lucide-react"

import {
  SidebarGroup,
  SidebarGroupContent,
  SidebarGroupLabel,
  SidebarMenu,
  SidebarMenuButton,
  SidebarMenuItem,
} from "@/components/ui/sidebar"

// Nav items reflect only what's actually built (Epics 01-06 land these
// incrementally) -- Epic 01's vault-settings page adds a "Settings" item
// here once it lands.
export function VaultNav() {
  const { vaultName } = useParams({ strict: false })

  if (!vaultName) {
    return null
  }

  return (
    <SidebarGroup>
      <SidebarGroupLabel>Vault</SidebarGroupLabel>
      <SidebarGroupContent>
        <SidebarMenu>
          <SidebarMenuItem>
            <SidebarMenuButton
              render={
                <Link to="/vaults/$vaultName/secrets" params={{ vaultName }} />
              }
            >
              <KeyRoundIcon />
              <span>Secrets</span>
            </SidebarMenuButton>
          </SidebarMenuItem>
        </SidebarMenu>
      </SidebarGroupContent>
    </SidebarGroup>
  )
}
