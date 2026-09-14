import { Link, useParams } from "@tanstack/react-router"
import { KeyRoundIcon, KeySquareIcon, SettingsIcon } from "lucide-react"

import {
  SidebarGroup,
  SidebarGroupContent,
  SidebarGroupLabel,
  SidebarMenu,
  SidebarMenuButton,
  SidebarMenuItem,
} from "@/components/ui/sidebar"

// Nav items reflect only what's actually built (Epics 01-06 land these
// incrementally) -- "Settings" was added by Epic 01's vault-settings page.
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
          <SidebarMenuItem>
            <SidebarMenuButton
              render={
                <Link to="/vaults/$vaultName/keys" params={{ vaultName }} />
              }
            >
              <KeySquareIcon />
              <span>Keys</span>
            </SidebarMenuButton>
          </SidebarMenuItem>
          <SidebarMenuItem>
            <SidebarMenuButton
              render={
                <Link to="/vaults/$vaultName/settings" params={{ vaultName }} />
              }
            >
              <SettingsIcon />
              <span>Settings</span>
            </SidebarMenuButton>
          </SidebarMenuItem>
        </SidebarMenu>
      </SidebarGroupContent>
    </SidebarGroup>
  )
}
