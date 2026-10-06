import { useMemo } from "react"
import { useQuery } from "@tanstack/react-query"
import { Link, useParams } from "@tanstack/react-router"
import { ChevronsUpDownIcon, VaultIcon } from "lucide-react"

import { listVaults } from "@/api/vaults"
import { VaultStatus } from "@/components/status-dot"
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

  /**
   * The MRU half of this list carries names only -- nothing tells us
   * whether those vaults are enabled -- so a status dot is rendered only
   * for entries the API actually described. Showing a hollow "Disabled"
   * dot for an unknown vault would be a claim we cannot make.
   */
  const vaults = useMemo(() => {
    const enabledByName = new Map(
      (data ?? []).map((vault) => [vault.name, vault.enabled])
    )
    const names = Array.from(
      new Set([...getRecentVaults(), ...enabledByName.keys()])
    )
    return names.map((name) => ({ name, enabled: enabledByName.get(name) }))
  }, [data])

  return (
    <SidebarMenu>
      <SidebarMenuItem>
        <DropdownMenu>
          <DropdownMenuTrigger render={<SidebarMenuButton size="lg" />}>
            <VaultIcon />
            <span className="truncate font-heading">
              {vaultName ?? "Select a vault"}
            </span>
            <ChevronsUpDownIcon className="ml-auto" />
          </DropdownMenuTrigger>
          <DropdownMenuContent>
            <DropdownMenuLabel>Vaults</DropdownMenuLabel>
            <DropdownMenuSeparator />
            {vaults.length === 0 && (
              <DropdownMenuItem disabled>No recent vaults</DropdownMenuItem>
            )}
            {vaults.map((vault) => (
              <DropdownMenuItem
                key={vault.name}
                render={
                  <Link
                    to="/vaults/$vaultName/secrets"
                    params={{ vaultName: vault.name }}
                  />
                }
              >
                <span className="truncate font-heading">{vault.name}</span>
                {vault.enabled !== undefined && (
                  <VaultStatus enabled={vault.enabled} className="ml-auto" />
                )}
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
