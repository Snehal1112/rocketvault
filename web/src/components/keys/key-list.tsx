import { useQuery } from "@tanstack/react-query"
import { Link } from "@tanstack/react-router"
import { CpuIcon, KeySquareIcon, ShieldAlertIcon } from "lucide-react"

import { type Key, listKeys } from "@/api/keys"
import { ApiError } from "@/api/types"
import { KeyCreateDialog } from "@/components/keys/key-create-dialog"
import { KeyStatus } from "@/components/keys/key-status"
import { summarizeKeys, type KeysSummary } from "@/components/keys/key-summary"
import { describeKeyMaterial, isHsmBacked } from "@/components/keys/key-type"
import { RESOURCE_CARD_LINK_CLASS } from "@/components/patterns/card-link-class"
import { CardGrid } from "@/components/patterns/card-grid"
import { ResourceListSkeleton } from "@/components/patterns/list-skeleton"
import { ResourceCardShell } from "@/components/patterns/resource-card"
import { StatGrid, StatTile } from "@/components/patterns/stat-tile"
import { Badge } from "@/components/ui/badge"
import {
  Empty,
  EmptyContent,
  EmptyDescription,
  EmptyHeader,
  EmptyMedia,
  EmptyTitle,
} from "@/components/ui/empty"
import { formatRelativeTime } from "@/lib/format"

function KeyStatRow({ summary }: { summary: KeysSummary }) {
  return (
    <StatGrid aria-label="Key counts" className="grid-cols-2 lg:grid-cols-4">
      <StatTile value={summary.total} label="Total" />
      <StatTile value={summary.hsmBacked} label="HSM-backed" />
      <StatTile value={summary.expiringSoon} label="Expiring soon" />
      <StatTile value={summary.unavailable} label="Unavailable" />
    </StatGrid>
  )
}

function KeyCard({
  vaultName,
  keyRecord,
}: {
  vaultName: string
  keyRecord: Key
}) {
  return (
    <Link
      to="/vaults/$vaultName/keys/$keyId"
      params={{ vaultName, keyId: keyRecord.id }}
      className={RESOURCE_CARD_LINK_CLASS}
    >
      <ResourceCardShell
        title={keyRecord.name}
        status={<KeyStatus keyRecord={keyRecord} />}
      >
        <span className="font-heading text-foreground">
          {describeKeyMaterial(keyRecord)}
        </span>
        <span>Created {formatRelativeTime(keyRecord.createdAt)}</span>
        {isHsmBacked(keyRecord.type) && (
          <span className="mt-1 inline-flex items-center gap-1.5 text-foreground">
            <CpuIcon className="size-3.5" />
            Stored in HSM
          </span>
        )}
        {keyRecord.tags.length > 0 && (
          <div className="mt-2 flex flex-wrap gap-1.5">
            {keyRecord.tags.slice(0, 3).map((tag) => (
              <Badge key={tag} variant="secondary" className="font-heading">
                {tag}
              </Badge>
            ))}
            {keyRecord.tags.length > 3 && (
              <Badge variant="secondary">+{keyRecord.tags.length - 3}</Badge>
            )}
          </div>
        )}
      </ResourceCardShell>
    </Link>
  )
}

export function KeyList({ vaultName }: { vaultName: string }) {
  const { data, isLoading, error } = useQuery({
    queryKey: ["keys", vaultName, "list"],
    queryFn: () => listKeys(vaultName),
  })

  if (isLoading) {
    return (
      <ResourceListSkeleton
        statCount={4}
        statGridClassName="grid-cols-2 lg:grid-cols-4"
        cardCount={3}
        cardHeightClassName="h-40"
      />
    )
  }

  // A denied read and an empty vault look identical if the error is swallowed,
  // and they call for opposite responses from the operator -- so the server's
  // own message is shown rather than an empty state.
  if (error) {
    return (
      <Empty>
        <EmptyHeader>
          <EmptyMedia variant="icon">
            <ShieldAlertIcon />
          </EmptyMedia>
          <EmptyTitle>Keys unavailable</EmptyTitle>
          <EmptyDescription>
            {error instanceof ApiError
              ? error.message
              : "Could not load keys for this vault."}
          </EmptyDescription>
        </EmptyHeader>
      </Empty>
    )
  }

  if (!data || data.length === 0) {
    return (
      <Empty>
        <EmptyHeader>
          <EmptyMedia variant="icon">
            <KeySquareIcon />
          </EmptyMedia>
          <EmptyTitle>No keys yet</EmptyTitle>
          <EmptyDescription>
            Generate an RSA or EC key to start signing, or import one you
            already hold.
          </EmptyDescription>
        </EmptyHeader>
        <EmptyContent>
          <KeyCreateDialog vaultName={vaultName} />
        </EmptyContent>
      </Empty>
    )
  }

  return (
    <div className="flex flex-col gap-6">
      <KeyStatRow summary={summarizeKeys(data)} />
      <CardGrid>
        {data.map((keyRecord) => (
          <KeyCard
            key={keyRecord.id}
            vaultName={vaultName}
            keyRecord={keyRecord}
          />
        ))}
      </CardGrid>
    </div>
  )
}
