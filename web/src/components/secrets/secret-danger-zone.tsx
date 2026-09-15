import { useState } from "react"
import { useMutation, useQueryClient } from "@tanstack/react-query"
import { useNavigate } from "@tanstack/react-router"

import { deleteSecret } from "@/api/secrets"
import { ApiError } from "@/api/types"
import { DangerAction, DangerZoneCard } from "@/components/patterns/danger-zone"
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

/**
 * Delete is a SOFT delete: the secret moves to the vault's deleted items and
 * stays recoverable for the vault's retention window. Purge -- the
 * irreversible half -- deliberately lives on the deleted-items screen
 * instead, so the two are never one mis-click apart.
 */
export function SecretDangerZone({
  vaultName,
  secretName,
  secretId,
}: {
  vaultName: string
  secretName: string
  secretId: string
}) {
  const navigate = useNavigate()
  const queryClient = useQueryClient()
  const [open, setOpen] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const mutation = useMutation({
    mutationFn: () => deleteSecret(vaultName, secretId),
    onSuccess: async () => {
      setOpen(false)
      await queryClient.invalidateQueries({ queryKey: ["secrets", vaultName] })
      navigate({ to: "/vaults/$vaultName/secrets", params: { vaultName } })
    },
    onError: (mutationError) => {
      // Close the confirm so the reason is visible rather than trapped
      // behind a modal.
      setOpen(false)
      setError(
        mutationError instanceof ApiError && mutationError.statusCode === 403
          ? "You don't have permission to delete secrets in this vault."
          : "Failed to delete secret."
      )
    },
  })

  return (
    <DangerZoneCard description="Deleting is reversible for as long as the vault's retention window lasts. Purging is not, and lives on the deleted-items screen.">
      <DangerAction
        title="Delete secret"
        description={
          <>
            Anything reading{" "}
            <span className="font-heading text-foreground">{secretName}</span>{" "}
            stops getting a value immediately. It stays recoverable from the
            vault's deleted items until the retention window closes, then it is
            purged automatically.
          </>
        }
        error={error}
      >
        <AlertDialog open={open} onOpenChange={setOpen}>
          <AlertDialogTrigger render={<Button variant="destructive" />}>
            Delete secret
          </AlertDialogTrigger>
          <AlertDialogContent>
            <AlertDialogHeader>
              <AlertDialogTitle>Delete {secretName}?</AlertDialogTitle>
              <AlertDialogDescription>
                Every application reading this secret starts failing as soon as
                you confirm. You can recover it from this vault's deleted items
                until the retention window closes.
              </AlertDialogDescription>
            </AlertDialogHeader>
            <AlertDialogFooter>
              <AlertDialogCancel>Cancel</AlertDialogCancel>
              <AlertDialogAction
                render={<Button variant="destructive" />}
                onClick={() => mutation.mutate()}
              >
                Confirm
              </AlertDialogAction>
            </AlertDialogFooter>
          </AlertDialogContent>
        </AlertDialog>
      </DangerAction>
    </DangerZoneCard>
  )
}
