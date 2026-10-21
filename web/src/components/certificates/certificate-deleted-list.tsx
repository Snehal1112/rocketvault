import { useState } from "react"
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import { ArchiveIcon, ShieldAlertIcon } from "lucide-react"

import {
  type DeletedCertificate,
  listDeletedCertificates,
  purgeCertificate,
  recoverCertificate,
} from "@/api/certificates"
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
 * Deleted certificates are a table, not a card grid: nothing here is
 * navigated into, the operator is scanning for one row to recover or purge
 * (design language doc, "Layout vocabulary").
 *
 * Only the four fields the deleted row actually carries are rendered -- id,
 * name, deleted_at, purge_protection. Unlike the deleted-secrets row there is
 * no created_at, and there is no GET for a single deleted certificate either,
 * so this list is the whole of what is knowable about a deleted certificate.
 */
export function CertificateDeletedList({ vaultName }: { vaultName: string }) {
  const queryClient = useQueryClient()
  const [error, setError] = useState<string | null>(null)
  const [notice, setNotice] = useState<string | null>(null)

  const {
    data,
    isLoading,
    error: loadError,
  } = useQuery({
    queryKey: ["certificates", vaultName, "deleted"],
    queryFn: () => listDeletedCertificates(vaultName),
  })

  async function refresh() {
    await queryClient.invalidateQueries({
      queryKey: ["certificates", vaultName],
    })
  }

  const recover = useMutation({
    mutationFn: (certificateId: string) =>
      recoverCertificate(vaultName, certificateId),
    onSuccess: async (result) => {
      setError(null)
      // The server's own wording, not a restatement of it -- if the backend
      // ever says something more specific, the operator sees that.
      setNotice(result.message)
      await refresh()
    },
    onError: (mutationError) => {
      setNotice(null)
      setError(
        mutationError instanceof ApiError
          ? mutationError.message
          : "Failed to recover the certificate."
      )
    },
  })

  const purge = useMutation({
    mutationFn: (certificateId: string) =>
      purgeCertificate(vaultName, certificateId),
    onSuccess: async () => {
      setError(null)
      setNotice(null)
      await refresh()
    },
    onError: (mutationError) => {
      setNotice(null)
      setError(
        mutationError instanceof ApiError
          ? mutationError.message
          : "Failed to purge the certificate."
      )
    },
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
          <EmptyTitle>Deleted certificates unavailable</EmptyTitle>
          <EmptyDescription>
            {loadError instanceof ApiError
              ? loadError.message
              : "Could not load deleted certificates for this vault."}
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
            Deleted certificates stay here, recoverable, until the vault's
            retention window passes.
          </EmptyDescription>
        </EmptyHeader>
      </Empty>
    )
  }

  return (
    <div className="flex flex-col gap-3">
      {notice && (
        <p role="status" className="text-sm text-muted-foreground">
          {notice}
        </p>
      )}
      {error && (
        <p role="alert" className="text-sm text-destructive">
          {error}
        </p>
      )}
      <Table>
        <TableHeader>
          <TableRow>
            <TableHead>Name</TableHead>
            <TableHead>Identifier</TableHead>
            <TableHead>Deleted</TableHead>
            <TableHead className="text-right">Actions</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {data.map((deleted) => (
            <DeletedCertificateRow
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

function DeletedCertificateRow({
  deleted,
  onRecover,
  onPurge,
  busy,
}: {
  deleted: DeletedCertificate
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
      <TableCell className="font-heading text-xs break-all text-muted-foreground">
        {deleted.id}
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
                  // Deliberately NOT disabled on purge_protection. That flag
                  // is only one of three independent protections -- the
                  // certificate's own, its vault's, and the instance-wide
                  // soft_delete.purge_protection -- and the last two are
                  // invisible to the client. A client-side guard would block
                  // purges the server would have allowed, and allow ones it
                  // would refuse. The server decides; its answer is shown.
                  disabled={busy}
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
                  This destroys the certificate and its policy outright. It can
                  no longer be recovered, renewed or reissued from this vault.
                  This cannot be undone.
                  {deleted.purgeProtection &&
                    " This certificate has purge protection enabled, so the server will most likely refuse — lift the protection first."}
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
