import { Link } from "@tanstack/react-router"
import { ShieldIcon } from "lucide-react"

import {
  SidebarGroup,
  SidebarGroupContent,
  SidebarGroupLabel,
  SidebarMenu,
  SidebarMenuButton,
  SidebarMenuItem,
} from "@/components/ui/sidebar"

// Epics 07-12 (users, service accounts, access policies, provisioning
// grants, audit, JWKS) each add their own item here as they land -- none of
// those are in scope yet, so this only links to the admin index placeholder.
export function AdminNav() {
  return (
    <SidebarGroup>
      <SidebarGroupLabel>Admin</SidebarGroupLabel>
      <SidebarGroupContent>
        <SidebarMenu>
          <SidebarMenuItem>
            <SidebarMenuButton render={<Link to="/admin" />}>
              <ShieldIcon />
              <span>Overview</span>
            </SidebarMenuButton>
          </SidebarMenuItem>
        </SidebarMenu>
      </SidebarGroupContent>
    </SidebarGroup>
  )
}
