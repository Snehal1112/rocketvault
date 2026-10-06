import { useQuery } from "@tanstack/react-query"
import { Link } from "@tanstack/react-router"
import { ShieldCheckIcon, VaultIcon } from "lucide-react"

import { listVaults, type Vault } from "@/api/vaults"
import { RESOURCE_CARD_LINK_CLASS } from "@/components/patterns/card-link-class"
import { CardGrid } from "@/components/patterns/card-grid"
import { ResourceListSkeleton } from "@/components/patterns/list-skeleton"
import { ResourceCardShell } from "@/components/patterns/resource-card"
import { StatGrid, StatTile } from "@/components/patterns/stat-tile"
import { VaultStatus } from "@/components/status-dot"
import { VaultCreateDialog } from "@/components/vaults/vault-create-dialog"
import {
  summarizeVaults,
  type VaultSummary,
} from "@/components/vaults/vault-summary"
import {
  Empty,
  EmptyContent,
  EmptyDescription,
  EmptyHeader,
  EmptyMedia,
  EmptyTitle,
} from "@/components/ui/empty"
import { formatRelativeTime } from "@/lib/format"

function VaultStatRow({ summary }: { summary: VaultSummary }) {
  return (
    <StatGrid aria-label="Vault counts">
      <StatTile value={summary.total} label="Total" />
      <StatTile value={summary.enabled} label="Enabled" />
      <StatTile value={summary.disabled} label="Disabled" />
    </StatGrid>
  )
}

function VaultCard({ vault }: { vault: Vault }) {
  return (
    <Link
      to="/vaults/$vaultName/secrets"
      params={{ vaultName: vault.name }}
      className={RESOURCE_CARD_LINK_CLASS}
    >
      <ResourceCardShell
        title={vault.name}
        status={<VaultStatus enabled={vault.enabled} />}
      >
        <span>{vault.retentionDays}-day retention</span>
        <span>Created {formatRelativeTime(vault.createdAt)}</span>
        {vault.purgeProtection && (
          <span className="mt-1 inline-flex items-center gap-1.5 text-foreground">
            <ShieldCheckIcon className="size-3.5" />
            Purge protection on
          </span>
        )}
      </ResourceCardShell>
    </Link>
  )
}

export function VaultList() {
  const { data, isLoading } = useQuery({
    queryKey: ["vaults", "list"],
    queryFn: () => listVaults(),
  })

  if (isLoading) {
    return (
      <ResourceListSkeleton
        statCount={3}
        cardCount={3}
        cardHeightClassName="h-36"
      />
    )
  }

  if (!data || data.length === 0) {
    return (
      <Empty>
        <EmptyHeader>
          <EmptyMedia variant="icon">
            <VaultIcon />
          </EmptyMedia>
          <EmptyTitle>No vaults yet</EmptyTitle>
          <EmptyDescription>
            Create your first vault to start storing secrets, keys, and
            certificates.
          </EmptyDescription>
        </EmptyHeader>
        <EmptyContent>
          <VaultCreateDialog />
        </EmptyContent>
      </Empty>
    )
  }

  return (
    <div className="flex flex-col gap-6">
      <VaultStatRow summary={summarizeVaults(data)} />
      <CardGrid>
        {data.map((vault) => (
          <VaultCard key={vault.id} vault={vault} />
        ))}
      </CardGrid>
    </div>
  )
}
