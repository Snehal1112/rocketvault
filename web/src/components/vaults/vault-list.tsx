import { useQuery } from "@tanstack/react-query"
import { Link } from "@tanstack/react-router"
import { ShieldCheckIcon, VaultIcon } from "lucide-react"

import { listVaults, type Vault } from "@/api/vaults"
import { VaultStatus } from "@/components/status-dot"
import { VaultCreateDialog } from "@/components/vaults/vault-create-dialog"
import {
  summarizeVaults,
  type VaultSummary,
} from "@/components/vaults/vault-summary"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import {
  Empty,
  EmptyContent,
  EmptyDescription,
  EmptyHeader,
  EmptyMedia,
  EmptyTitle,
} from "@/components/ui/empty"
import { Skeleton } from "@/components/ui/skeleton"
import { formatRelativeTime } from "@/lib/format"

function StatTile({ value, label }: { value: number; label: string }) {
  return (
    <Card size="sm" className="gap-0">
      <CardContent>
        <p className="font-heading text-2xl leading-none font-medium tabular-nums">
          {value}
        </p>
        <p className="mt-1.5 text-xs text-muted-foreground">{label}</p>
      </CardContent>
    </Card>
  )
}

function VaultStatRow({ summary }: { summary: VaultSummary }) {
  return (
    <div className="grid grid-cols-3 gap-3 sm:gap-4">
      <StatTile value={summary.total} label="Total" />
      <StatTile value={summary.enabled} label="Enabled" />
      <StatTile value={summary.disabled} label="Disabled" />
    </div>
  )
}

function VaultCard({ vault }: { vault: Vault }) {
  return (
    <Link
      to="/vaults/$vaultName/secrets"
      params={{ vaultName: vault.name }}
      className="group block h-full rounded-4xl outline-none focus-visible:ring-3 focus-visible:ring-ring/30"
    >
      <Card
        size="sm"
        className="h-full gap-3 transition-shadow duration-150 group-hover:ring-foreground/15 dark:group-hover:ring-foreground/25"
      >
        <CardHeader className="flex flex-row items-center justify-between gap-3">
          <CardTitle className="truncate">{vault.name}</CardTitle>
          <VaultStatus enabled={vault.enabled} />
        </CardHeader>
        <CardContent className="flex flex-col gap-1 text-xs text-muted-foreground">
          <span>{vault.retentionDays}-day retention</span>
          <span>Created {formatRelativeTime(vault.createdAt)}</span>
          {vault.purgeProtection && (
            <span className="mt-1 inline-flex items-center gap-1.5 text-foreground">
              <ShieldCheckIcon className="size-3.5" />
              Purge protection on
            </span>
          )}
        </CardContent>
      </Card>
    </Link>
  )
}

function VaultListSkeleton() {
  return (
    <div className="flex flex-col gap-6">
      <div className="grid grid-cols-3 gap-3 sm:gap-4">
        {[0, 1, 2].map((tile) => (
          <Skeleton key={tile} className="h-20 rounded-4xl" />
        ))}
      </div>
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-3">
        {[0, 1, 2].map((card) => (
          <Skeleton key={card} className="h-36 rounded-4xl" />
        ))}
      </div>
    </div>
  )
}

export function VaultList() {
  const { data, isLoading } = useQuery({
    queryKey: ["vaults", "list"],
    queryFn: () => listVaults(),
  })

  if (isLoading) {
    return <VaultListSkeleton />
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
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-3">
        {data.map((vault) => (
          <VaultCard key={vault.id} vault={vault} />
        ))}
      </div>
    </div>
  )
}
