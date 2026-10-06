import { useState } from "react"
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"

import {
  type DeletedSecret,
  listDeletedSecrets,
  purgeSecret,
  restoreDeletedSecret,
} from "@/api/secrets"
import { ApiError } from "@/api/types"
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
  AlertDialogTrigger,
} from "@/components/ui/alert-dialog"
import { Button } from "@/components/ui/button"
import {
  Empty,
  EmptyDescription,
  EmptyHeader,
  EmptyMedia,
  EmptyTitle,
} from "@/components/ui/empty"
import { Skeleton } from "@/components/ui/skeleton"
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table"
import { formatRelativeTime } from "@/lib/format"
import { Trash2Icon } from "lucide-react"

/**
 * Deleted items are a table, not a card grid: nothing here is opened, each
 * row is scanned and then acted on (design doc's cards-vs-table rule).
 *
 * Recover and purge are separate permissions on the backend and neither
 * button is hidden based on the other. A deleted-secret row carries no
 * purge-protection or scheduled-purge field at all
 * (../../../api/soft_delete.go:185-191 -- unlike deleted keys and certs),
 * so purge cannot be pre-disabled here; a refusal only arrives on attempt,
 * and is surfaced inline when it does.
 */
export function SecretDeletedList({ vaultName }: { vaultName: string }) {
  const { data, isLoading, error } = useQuery({
    queryKey: ["secrets", vaultName, "deleted"],
    queryFn: () => listDeletedSecrets(vaultName),
  })

  if (isLoading) {
    return (
      <div className="flex flex-col gap-2">
        <Skeleton className="h-10 w-full" />
        <Skeleton className="h-10 w-full" />
      </div>
    )
  }

  if (error) {
    return (
      <Empty>
        <EmptyHeader>
          <EmptyMedia variant="icon">
            <Trash2Icon />
          </EmptyMedia>
          <EmptyTitle>Deleted secrets are unavailable</EmptyTitle>
          <EmptyDescription>
            {error instanceof ApiError && error.statusCode === 403
              ? "Listing deleted secrets needs a role that grants it in this vault."
              : error instanceof Error
                ? error.message
                : "This vault's deleted secrets could not be read."}
          </EmptyDescription>
        </EmptyHeader>
      </Empty>
    )
  }

  const deleted = data ?? []

  if (deleted.length === 0) {
    return (
      <Empty>
        <EmptyHeader>
          <EmptyMedia variant="icon">
            <Trash2Icon />
          </EmptyMedia>
          <EmptyTitle>Nothing deleted</EmptyTitle>
          <EmptyDescription>
            Deleted secrets wait here until the vault's retention window closes,
            then they are purged automatically.
          </EmptyDescription>
        </EmptyHeader>
      </Empty>
    )
  }

  return (
    <Table>
      <TableHeader>
        <TableRow>
          <TableHead>Name</TableHead>
          <TableHead>Version</TableHead>
          <TableHead>Deleted</TableHead>
          <TableHead className="text-right">Actions</TableHead>
        </TableRow>
      </TableHeader>
      <TableBody>
        {deleted.map((secret) => (
          <DeletedSecretRow
            key={secret.id}
            vaultName={vaultName}
            secret={secret}
          />
        ))}
      </TableBody>
    </Table>
  )
}

function DeletedSecretRow({
  vaultName,
  secret,
}: {
  vaultName: string
  secret: DeletedSecret
}) {
  const queryClient = useQueryClient()
  const [purgeOpen, setPurgeOpen] = useState(false)
  const [error, setError] = useState<string | null>(null)

  async function invalidate() {
    await queryClient.invalidateQueries({ queryKey: ["secrets", vaultName] })
  }

  const recoverMutation = useMutation({
    mutationFn: () => restoreDeletedSecret(vaultName, secret.id),
    onSuccess: async () => {
      setError(null)
      await invalidate()
    },
    onError: (mutationError) => {
      setError(
        mutationError instanceof ApiError && mutationError.statusCode === 403
          ? "You don't have permission to recover secrets in this vault."
          : "Failed to recover secret."
      )
    },
  })

  const purgeMutation = useMutation({
    mutationFn: () => purgeSecret(vaultName, secret.id),
    onSuccess: async () => {
      setPurgeOpen(false)
      setError(null)
      await invalidate()
    },
    onError: (mutationError) => {
      setPurgeOpen(false)
      setError(
        mutationError instanceof ApiError && mutationError.statusCode === 403
          ? "This secret is purge-protected, or you lack the purge permission in this vault."
          : "Failed to purge secret."
      )
    },
  })

  const busy = recoverMutation.isPending || purgeMutation.isPending

  return (
    <>
      <TableRow>
        <TableCell className="font-heading">{secret.name}</TableCell>
        <TableCell className="font-heading text-muted-foreground">
          v{secret.version}
        </TableCell>
        <TableCell className="text-muted-foreground">
          {secret.deletedAt ? formatRelativeTime(secret.deletedAt) : "unknown"}
        </TableCell>
        <TableCell>
          <div className="flex justify-end gap-2">
            <Button
              type="button"
              variant="outline"
              size="sm"
              disabled={busy}
              onClick={() => recoverMutation.mutate()}
            >
              {recoverMutation.isPending ? "Recovering…" : "Recover"}
            </Button>
            <AlertDialog open={purgeOpen} onOpenChange={setPurgeOpen}>
              <AlertDialogTrigger
                render={
                  <Button variant="destructive" size="sm" disabled={busy} />
                }
              >
                Purge
              </AlertDialogTrigger>
              <AlertDialogContent>
                <AlertDialogHeader>
                  <AlertDialogTitle>
                    Permanently purge {secret.name}?
                  </AlertDialogTitle>
                  <AlertDialogDescription>
                    This destroys the secret and all {secret.version} of its
                    versions outright. There is no recovery window and no backup
                    taken on your behalf — this cannot be undone.
                  </AlertDialogDescription>
                </AlertDialogHeader>
                <AlertDialogFooter>
                  <AlertDialogCancel>Cancel</AlertDialogCancel>
                  <AlertDialogAction
                    render={<Button variant="destructive" />}
                    onClick={() => purgeMutation.mutate()}
                  >
                    Confirm
                  </AlertDialogAction>
                </AlertDialogFooter>
              </AlertDialogContent>
            </AlertDialog>
          </div>
        </TableCell>
      </TableRow>
      {error && (
        <TableRow>
          <TableCell colSpan={4}>
            <p role="alert" className="text-sm text-destructive">
              {error}
            </p>
          </TableCell>
        </TableRow>
      )}
    </>
  )
}
