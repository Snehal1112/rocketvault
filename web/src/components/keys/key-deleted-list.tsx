import { useState } from "react"
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import { ArchiveIcon, ShieldAlertIcon } from "lucide-react"

import {
  type DeletedKey,
  listDeletedKeys,
  purgeKey,
  restoreDeletedKey,
} from "@/api/keys"
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

/**
 * Deleted keys are a table, not a card grid: nothing here is navigated into,
 * the operator is scanning for one row to recover or purge (design language
 * doc, "Layout vocabulary").
 */
export function KeyDeletedList({ vaultName }: { vaultName: string }) {
  const queryClient = useQueryClient()
  const [error, setError] = useState<string | null>(null)

  const {
    data,
    isLoading,
    error: loadError,
  } = useQuery({
    queryKey: ["keys", vaultName, "deleted"],
    queryFn: () => listDeletedKeys(vaultName),
  })

  async function refresh() {
    await queryClient.invalidateQueries({ queryKey: ["keys", vaultName] })
  }

  const recover = useMutation({
    mutationFn: (keyId: string) => restoreDeletedKey(vaultName, keyId),
    onSuccess: async () => {
      setError(null)
      await refresh()
    },
    onError: (mutationError) =>
      setError(
        mutationError instanceof ApiError
          ? mutationError.message
          : "Failed to recover the key."
      ),
  })

  const purge = useMutation({
    mutationFn: (keyId: string) => purgeKey(vaultName, keyId),
    onSuccess: async () => {
      setError(null)
      await refresh()
    },
    onError: (mutationError) =>
      setError(
        mutationError instanceof ApiError
          ? mutationError.message
          : "Failed to purge the key."
      ),
  })

  if (isLoading) {
    return <Skeleton className="h-48 w-full rounded-4xl" />
  }

  if (loadError) {
    return (
      <Empty>
        <EmptyHeader>
          <EmptyMedia variant="icon">
            <ShieldAlertIcon />
          </EmptyMedia>
          <EmptyTitle>Deleted keys unavailable</EmptyTitle>
          <EmptyDescription>
            {loadError instanceof ApiError
              ? loadError.message
              : "Could not load deleted keys for this vault."}
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
            <ArchiveIcon />
          </EmptyMedia>
          <EmptyTitle>Nothing deleted</EmptyTitle>
          <EmptyDescription>
            Deleted keys stay here, recoverable, until the vault's retention
            window passes.
          </EmptyDescription>
        </EmptyHeader>
      </Empty>
    )
  }

  return (
    <div className="flex flex-col gap-3">
      {error && (
        <p role="alert" className="text-sm text-destructive">
          {error}
        </p>
      )}
      <Table>
        <TableHeader>
          <TableRow>
            <TableHead>Name</TableHead>
            <TableHead>Type</TableHead>
            <TableHead>Deleted</TableHead>
            <TableHead className="text-right">Actions</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {data.map((deleted) => (
            <DeletedKeyRow
              key={deleted.id}
              deleted={deleted}
              onRecover={() => recover.mutate(deleted.id)}
              onPurge={() => purge.mutate(deleted.id)}
              busy={recover.isPending || purge.isPending}
            />
          ))}
        </TableBody>
      </Table>
    </div>
  )
}

function DeletedKeyRow({
  deleted,
  onRecover,
  onPurge,
  busy,
}: {
  deleted: DeletedKey
  onRecover: () => void
  onPurge: () => void
  busy: boolean
}) {
  const [confirmOpen, setConfirmOpen] = useState(false)

  function handlePurge() {
    setConfirmOpen(false)
    onPurge()
  }

  return (
    <TableRow>
      <TableCell className="font-heading">{deleted.name}</TableCell>
      <TableCell className="font-heading text-muted-foreground">
        {deleted.type}
      </TableCell>
      <TableCell className="text-muted-foreground">
        {deleted.deletedAt ? formatRelativeTime(deleted.deletedAt) : "unknown"}
      </TableCell>
      <TableCell>
        <div className="flex items-center justify-end gap-2">
          {deleted.purgeProtection && (
            <span className="text-xs text-muted-foreground">
              Purge protected
            </span>
          )}
          <Button
            variant="outline"
            size="sm"
            disabled={busy}
            onClick={onRecover}
          >
            Recover
          </Button>
          <AlertDialog open={confirmOpen} onOpenChange={setConfirmOpen}>
            <AlertDialogTrigger
              render={
                <Button
                  variant="destructive"
                  size="sm"
                  // The backend refuses a protected purge with a 403 anyway;
                  // disabling here just saves the round trip.
                  disabled={busy || deleted.purgeProtection}
                />
              }
            >
              Purge
            </AlertDialogTrigger>
            <AlertDialogContent>
              <AlertDialogHeader>
                <AlertDialogTitle>
                  Permanently purge {deleted.name}?
                </AlertDialogTitle>
                <AlertDialogDescription>
                  This destroys the key and every version of it outright.
                  Anything signed or encrypted with it can no longer be verified
                  or decrypted. This cannot be undone.
                </AlertDialogDescription>
              </AlertDialogHeader>
              <AlertDialogFooter>
                <AlertDialogCancel>Cancel</AlertDialogCancel>
                <AlertDialogAction
                  render={<Button variant="destructive" />}
                  onClick={handlePurge}
                >
                  Purge permanently
                </AlertDialogAction>
              </AlertDialogFooter>
            </AlertDialogContent>
          </AlertDialog>
        </div>
      </TableCell>
    </TableRow>
  )
}
