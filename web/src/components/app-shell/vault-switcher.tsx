import { useMemo } from "react"
import { useQuery } from "@tanstack/react-query"
import { Link, useParams } from "@tanstack/react-router"
import { ChevronsUpDownIcon, VaultIcon } from "lucide-react"

import { listVaults } from "@/api/vaults"
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu"
import {
  SidebarMenu,
  SidebarMenuButton,
  SidebarMenuItem,
} from "@/components/ui/sidebar"
import { useAuth } from "@/lib/auth/auth-context"
import { getRecentVaults } from "@/lib/auth/session-storage"

/**
 * Merges the client-side MRU vault list (session-storage.ts) with a live
 * GET /vaults call (src/api/vaults.ts) for admin-tier sessions. Mitigates a
 * real backend gap (design doc §Deferred): GET /vaults only returns vaults
 * the caller can *manage*, not every vault they hold a data-plane role in,
 * so a plain Secrets User has no API-driven way to discover their own
 * vault list -- the MRU list is the only source for them.
 */
export function VaultSwitcher() {
  const { vaultName } = useParams({ strict: false })
  const { isGlobalAdmin } = useAuth()

  const { data } = useQuery({
    queryKey: ["vaults", "switcher"],
    queryFn: () => listVaults(),
    enabled: isGlobalAdmin,
  })

  const vaultNames = useMemo(() => {
    const recent = getRecentVaults()
    const managed = data?.map((vault) => vault.name) ?? []
    return Array.from(new Set([...recent, ...managed]))
  }, [data])

  return (
    <SidebarMenu>
      <SidebarMenuItem>
        <DropdownMenu>
          <DropdownMenuTrigger render={<SidebarMenuButton size="lg" />}>
            <VaultIcon />
            <span className="truncate">{vaultName ?? "Select a vault"}</span>
            <ChevronsUpDownIcon className="ml-auto" />
          </DropdownMenuTrigger>
          <DropdownMenuContent>
            <DropdownMenuLabel>Vaults</DropdownMenuLabel>
            <DropdownMenuSeparator />
            {vaultNames.length === 0 && (
              <DropdownMenuItem disabled>No recent vaults</DropdownMenuItem>
            )}
            {vaultNames.map((name) => (
              <DropdownMenuItem
                key={name}
                render={
                  <Link
                    to="/vaults/$vaultName/secrets"
                    params={{ vaultName: name }}
                  />
                }
              >
                {name}
              </DropdownMenuItem>
            ))}
            <DropdownMenuSeparator />
            <DropdownMenuItem render={<Link to="/vaults" />}>
              Browse all vaults
            </DropdownMenuItem>
          </DropdownMenuContent>
        </DropdownMenu>
      </SidebarMenuItem>
    </SidebarMenu>
  )
}
