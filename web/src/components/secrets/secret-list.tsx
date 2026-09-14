import { useState } from "react"
import { useQuery } from "@tanstack/react-query"
import { Link } from "@tanstack/react-router"
import { KeyRoundIcon, SearchIcon, Trash2Icon } from "lucide-react"

import {
  listDeletedSecrets,
  listSecrets,
  MAX_SECRETS_PER_PAGE,
  type Secret,
} from "@/api/secrets"
import { SecretCreateDialog } from "@/components/secrets/secret-create-dialog"
import {
  filterSecrets,
  summarizeSecrets,
  type SecretSummary,
} from "@/components/secrets/secret-summary"
import { StatusDot } from "@/components/status-dot"
import { Badge } from "@/components/ui/badge"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import {
  Empty,
  EmptyContent,
  EmptyDescription,
  EmptyHeader,
  EmptyMedia,
  EmptyTitle,
} from "@/components/ui/empty"
import { Input } from "@/components/ui/input"
import { Skeleton } from "@/components/ui/skeleton"
import { formatRelativeTime } from "@/lib/format"

function StatTile({ value, label }: { value: number | string; label: string }) {
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

function SecretStatRow({
  summary,
  vaultName,
}: {
  summary: SecretSummary
  vaultName: string
}) {
  return (
    <section
      aria-label="Secret counts"
      className="grid grid-cols-3 gap-3 sm:gap-4"
    >
      <StatTile value={summary.total} label="Total" />
      <StatTile value={summary.enabled} label="Enabled" />
      {summary.deleted === null ? (
        <StatTile value="—" label="Deleted" />
      ) : (
        <Link
          to="/vaults/$vaultName/secrets/deleted"
          params={{ vaultName }}
          className="rounded-4xl outline-none focus-visible:ring-3 focus-visible:ring-ring/30"
        >
          <StatTile value={summary.deleted} label="Deleted" />
        </Link>
      )}
    </section>
  )
}

/** One secret as a card the operator opens, per the design doc's
 * cards-for-navigation / tables-for-scanning rule. */
function SecretCard({
  secret,
  vaultName,
}: {
  secret: Secret
  vaultName: string
}) {
  return (
    <Link
      to="/vaults/$vaultName/secrets/$secretId"
      params={{ vaultName, secretId: secret.id }}
      className="group block h-full rounded-4xl outline-none focus-visible:ring-3 focus-visible:ring-ring/30"
    >
      <Card
        size="sm"
        className="h-full gap-3 transition-shadow duration-150 group-hover:ring-foreground/15 dark:group-hover:ring-foreground/25"
      >
        <CardHeader className="flex flex-row items-center justify-between gap-3">
          <CardTitle className="truncate">{secret.name}</CardTitle>
          <StatusDot
            tone={secret.enabled ? "on" : "off"}
            label={secret.enabled ? "Enabled" : "Disabled"}
          />
        </CardHeader>
        <CardContent className="flex flex-col gap-2 text-xs text-muted-foreground">
          <span>
            <span className="font-heading">v{secret.version}</span> · created{" "}
            {formatRelativeTime(secret.createdAt)}
          </span>
          {secret.tags && secret.tags.length > 0 && (
            <div className="flex flex-wrap gap-1.5">
              {secret.tags.map((tag) => (
                <Badge key={tag} variant="secondary" className="font-heading">
                  {tag}
                </Badge>
              ))}
            </div>
          )}
        </CardContent>
      </Card>
    </Link>
  )
}

function SecretListSkeleton() {
  return (
    <div className="flex flex-col gap-6">
      <div className="grid grid-cols-3 gap-3 sm:gap-4">
        {[0, 1, 2].map((tile) => (
          <Skeleton key={tile} className="h-20 rounded-4xl" />
        ))}
      </div>
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-3">
        {[0, 1, 2, 3, 4, 5].map((card) => (
          <Skeleton key={card} className="h-32 rounded-4xl" />
        ))}
      </div>
    </div>
  )
}

export function SecretList({ vaultName }: { vaultName: string }) {
  const [query, setQuery] = useState("")

  const { data, isLoading, error } = useQuery({
    queryKey: ["secrets", vaultName, "list"],
    queryFn: () =>
      listSecrets(vaultName, { page: 0, perPage: MAX_SECRETS_PER_PAGE }),
  })

  // Listing deleted secrets is its own data action, so this query is kept
  // separate and its failure is absorbed: a caller who can list live secrets
  // but not deleted ones still gets the grid, with the count shown as "—"
  // rather than a misleading zero.
  const { data: deleted, isError: deletedUnavailable } = useQuery({
    queryKey: ["secrets", vaultName, "deleted"],
    queryFn: () => listDeletedSecrets(vaultName),
    retry: false,
  })

  if (isLoading) {
    return <SecretListSkeleton />
  }

  if (error) {
    return (
      <Empty>
        <EmptyHeader>
          <EmptyMedia variant="icon">
            <KeyRoundIcon />
          </EmptyMedia>
          <EmptyTitle>Secrets are unavailable</EmptyTitle>
          <EmptyDescription>
            {error instanceof Error
              ? error.message
              : "This vault's secrets could not be read."}
          </EmptyDescription>
        </EmptyHeader>
      </Empty>
    )
  }

  const secrets = data ?? []

  if (secrets.length === 0) {
    return (
      <Empty>
        <EmptyHeader>
          <EmptyMedia variant="icon">
            <KeyRoundIcon />
          </EmptyMedia>
          <EmptyTitle>No secrets in this vault</EmptyTitle>
          <EmptyDescription>
            Store a connection string, an API token, or anything else an
            application needs but should never hold in its own config.
          </EmptyDescription>
        </EmptyHeader>
        <EmptyContent>
          <SecretCreateDialog vaultName={vaultName} />
        </EmptyContent>
      </Empty>
    )
  }

  const deletedCount = deletedUnavailable ? null : (deleted?.length ?? null)
  const visible = filterSecrets(secrets, query)

  return (
    <div className="flex flex-col gap-6">
      <SecretStatRow
        summary={summarizeSecrets(secrets, deletedCount)}
        vaultName={vaultName}
      />

      <div className="relative max-w-sm">
        <SearchIcon
          aria-hidden="true"
          className="pointer-events-none absolute top-1/2 left-3 size-4 -translate-y-1/2 text-muted-foreground"
        />
        <Input
          aria-label="Filter secrets"
          placeholder="Filter by name or tag"
          value={query}
          onChange={(event) => setQuery(event.target.value)}
          className="pl-9"
        />
      </div>

      {visible.length === 0 ? (
        <Empty>
          <EmptyHeader>
            <EmptyMedia variant="icon">
              <SearchIcon />
            </EmptyMedia>
            <EmptyTitle>No match</EmptyTitle>
            <EmptyDescription>
              No secret in this vault matches “{query}”.
            </EmptyDescription>
          </EmptyHeader>
        </Empty>
      ) : (
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-3">
          {visible.map((secret) => (
            <SecretCard key={secret.id} secret={secret} vaultName={vaultName} />
          ))}
        </div>
      )}

      {secrets.length === MAX_SECRETS_PER_PAGE && (
        <p className="text-xs text-muted-foreground">
          Showing the first {MAX_SECRETS_PER_PAGE} secrets — the API caps a page
          at that size and reports no total, so there may be more.
        </p>
      )}

      {deletedCount !== null && deletedCount > 0 && (
        <Link
          to="/vaults/$vaultName/secrets/deleted"
          params={{ vaultName }}
          className="inline-flex w-fit items-center gap-2 text-sm text-muted-foreground underline-offset-4 hover:text-foreground hover:underline"
        >
          <Trash2Icon className="size-4" />
          {deletedCount} deleted {deletedCount === 1 ? "secret" : "secrets"} can
          still be recovered
        </Link>
      )}
    </div>
  )
}
