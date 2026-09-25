import { useState } from "react"
import { useMutation, useQueryClient } from "@tanstack/react-query"
import { useNavigate } from "@tanstack/react-router"

import { deleteKey } from "@/api/keys"
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
 * Soft-delete only. Purging a key is done from the deleted-keys tab, because
 * the backend has no purge route for a live key -- it has to be deleted
 * first, and the two are granted by different data actions.
 */
export function KeyDangerZone({
  vaultName,
  keyId,
  keyName,
}: {
  vaultName: string
  keyId: string
  keyName: string
}) {
  const navigate = useNavigate()
  const queryClient = useQueryClient()
  const [open, setOpen] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const remove = useMutation({
    mutationFn: () => deleteKey(vaultName, keyId),
    onSuccess: async () => {
      setOpen(false)
      await queryClient.invalidateQueries({ queryKey: ["keys", vaultName] })
      navigate({ to: "/vaults/$vaultName/keys", params: { vaultName } })
    },
    onError: (mutationError) => {
      // Close the dialog so the error is readable and the rest of the page is
      // no longer inert behind a modal.
      setOpen(false)
      setError(
        mutationError instanceof ApiError
          ? mutationError.message
          : "Failed to delete the key."
      )
    },
  })

  return (
    <DangerZoneCard description="Deleting is reversible for as long as the vault's retention window lasts. Purging, from the deleted-keys tab, is not.">
      <DangerAction
        title="Delete key"
        description={
          <>
            Every signature, verification, encryption and wrap request against{" "}
            <span className="font-heading text-foreground">{keyName}</span>{" "}
            starts failing immediately. It can be recovered from the
            deleted-keys tab until the retention window passes.
          </>
        }
        error={error}
      >
        <AlertDialog open={open} onOpenChange={setOpen}>
          <AlertDialogTrigger render={<Button variant="destructive" />}>
            Delete key
          </AlertDialogTrigger>
          <AlertDialogContent>
            <AlertDialogHeader>
              <AlertDialogTitle>Delete {keyName}?</AlertDialogTitle>
              <AlertDialogDescription>
                Anything depending on this key stops working now. The key and
                all of its versions stay recoverable from the deleted-keys tab
                until the vault's retention window expires, after which they are
                purged automatically.
              </AlertDialogDescription>
            </AlertDialogHeader>
            <AlertDialogFooter>
              <AlertDialogCancel>Cancel</AlertDialogCancel>
              <AlertDialogAction
                render={<Button variant="destructive" />}
                onClick={() => remove.mutate()}
              >
                Delete
              </AlertDialogAction>
            </AlertDialogFooter>
          </AlertDialogContent>
        </AlertDialog>
      </DangerAction>
    </DangerZoneCard>
  )
}
