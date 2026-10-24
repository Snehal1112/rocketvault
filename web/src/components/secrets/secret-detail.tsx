import { useState } from "react"
import { useMutation, useQuery } from "@tanstack/react-query"
import { Link } from "@tanstack/react-router"
import { ArrowLeftIcon, DownloadIcon, KeyRoundIcon } from "lucide-react"

import { backupSecret, getSecret } from "@/api/secrets"
import { ApiError } from "@/api/types"
import { downloadText } from "@/components/secrets/download"
import { SecretDangerZone } from "@/components/secrets/secret-danger-zone"
import { SecretEditForm } from "@/components/secrets/secret-edit-form"
import { SecretValue } from "@/components/secrets/secret-value"
import { SecretVersions } from "@/components/secrets/secret-versions"
import { StatusDot } from "@/components/status-dot"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card"
import {
  Empty,
  EmptyDescription,
  EmptyHeader,
  EmptyMedia,
  EmptyTitle,
} from "@/components/ui/empty"
import { Skeleton } from "@/components/ui/skeleton"
import { formatRelativeTime } from "@/lib/format"

/**
 * A detail screen, so it is sectioned into cards by concern rather than one
 * long form (visual design language doc, "Detail/settings screens"): what
 * the value is, what its properties are, what it used to be, how to take a
 * copy, and how to get rid of it.
 */
export function SecretDetail({
  vaultName,
  secretId,
}: {
  vaultName: string
  secretId: string
}) {
  const {
    data: secret,
    isLoading,
    error,
  } = useQuery({
    queryKey: ["secrets", vaultName, "detail", secretId],
    queryFn: () => getSecret(vaultName, secretId),
  })

  if (isLoading) {
    return (
      <div className="flex flex-col gap-6">
        <Skeleton className="h-10 w-64 rounded-3xl" />
        <Skeleton className="h-32 w-full rounded-4xl" />
        <Skeleton className="h-64 w-full rounded-4xl" />
      </div>
    )
  }

  if (error || !secret) {
    return (
      <Empty>
        <EmptyHeader>
          <EmptyMedia variant="icon">
            <KeyRoundIcon />
          </EmptyMedia>
          <EmptyTitle>Secret unavailable</EmptyTitle>
          <EmptyDescription>
            {error instanceof ApiError && error.statusCode === 404
              ? "This secret does not exist in this vault, or it has been deleted."
              : error instanceof Error
                ? error.message
                : "This secret could not be read."}
          </EmptyDescription>
        </EmptyHeader>
      </Empty>
    )
  }

  return (
    <div className="flex flex-col gap-6">
      <header className="flex flex-col gap-3">
        <Link
          to="/vaults/$vaultName/secrets"
          params={{ vaultName }}
          className="inline-flex w-fit items-center gap-1.5 text-sm text-muted-foreground underline-offset-4 hover:text-foreground hover:underline"
        >
          <ArrowLeftIcon className="size-4" />
          All secrets
        </Link>
        <div className="flex flex-wrap items-center gap-3">
          <h1 className="font-heading text-2xl font-medium tracking-tight">
            {secret.name}
          </h1>
          <StatusDot
            tone={secret.enabled ? "on" : "off"}
            label={secret.enabled ? "Enabled" : "Disabled"}
          />
        </div>
        <div className="flex flex-wrap items-center gap-2 text-xs text-muted-foreground">
          <Badge variant="secondary" className="font-heading">
            v{secret.version}
          </Badge>
          {secret.contentType && (
            <Badge variant="outline" className="font-heading">
              {secret.contentType}
            </Badge>
          )}
          <span>Created {formatRelativeTime(secret.createdAt)}</span>
          {secret.expiresAt && (
            <span>Expires {new Date(secret.expiresAt).toLocaleString()}</span>
          )}
          {secret.tags?.map((tag) => (
            <Badge key={tag} variant="secondary" className="font-heading">
              {tag}
            </Badge>
          ))}
        </div>
      </header>

      <Card>
        <CardHeader>
          <CardTitle>Value</CardTitle>
          <CardDescription>
            Hidden until you ask for it. Copy works without putting it on
            screen.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <SecretValue value={secret.value} />
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Properties</CardTitle>
          <CardDescription>
            Rename, rotate the value, or take it out of service.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <SecretEditForm vaultName={vaultName} secret={secret} />
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Version history</CardTitle>
          <CardDescription>
            Every saved value, oldest kept alongside the current one.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <SecretVersions
            vaultName={vaultName}
            secretId={secret.id}
            currentVersion={secret.version}
          />
        </CardContent>
      </Card>

      <SecretBackupCard
        vaultName={vaultName}
        secretId={secret.id}
        secretName={secret.name}
      />

      <SecretDangerZone
        vaultName={vaultName}
        secretId={secret.id}
        secretName={secret.name}
      />
    </div>
  )
}

function SecretBackupCard({
  vaultName,
  secretId,
  secretName,
}: {
  vaultName: string
  secretId: string
  secretName: string
}) {
  const [error, setError] = useState<string | null>(null)

  const mutation = useMutation({
    mutationFn: () => backupSecret(vaultName, secretId),
    onSuccess: (blob) => {
      setError(null)
      downloadText(blob, `${secretName}-backup.txt`, "text/plain")
    },
    onError: (mutationError) => {
      setError(
        mutationError instanceof ApiError
          ? mutationError.message
          : "Failed to back up secret."
      )
    },
  })

  return (
    <Card>
      <CardHeader>
        <CardTitle>Backup</CardTitle>
        <CardDescription>
          Downloads a restorable copy of this secret and all of its past values.
        </CardDescription>
      </CardHeader>
      <CardContent className="flex flex-col gap-3">
        {/* The backend's blob is base64-ENCODED, not encrypted
            (internal/backup/item_backup.go:152-156), and holds every
            historical plaintext. Saying so is not optional: an operator who
            believes it is encrypted will store it somewhere it should not
            be. */}
        <p className="max-w-[60ch] text-sm text-muted-foreground">
          The file is base64-encoded, <strong>not encrypted</strong>, and
          contains every value this secret has ever held in plain text. Treat
          the download exactly as you would the secret itself.
        </p>
        <Button
          type="button"
          variant="outline"
          className="w-fit"
          onClick={() => mutation.mutate()}
          disabled={mutation.isPending}
        >
          <DownloadIcon />
          {mutation.isPending ? "Preparing…" : "Download backup"}
        </Button>
        {error && (
          <p role="alert" className="text-sm text-destructive">
            {error}
          </p>
        )}
      </CardContent>
    </Card>
  )
}
