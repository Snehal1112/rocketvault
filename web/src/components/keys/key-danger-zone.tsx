import { useState } from "react"
import { useMutation, useQueryClient } from "@tanstack/react-query"
import { useNavigate } from "@tanstack/react-router"

import { deleteKey } from "@/api/keys"
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
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card"

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
    <Card className="border border-destructive/30 ring-destructive/10 dark:ring-destructive/20">
      <CardHeader>
        <CardTitle className="text-destructive">Danger zone</CardTitle>
        <CardDescription>
          Deleting is reversible for as long as the vault's retention window
          lasts. Purging, from the deleted-keys tab, is not.
        </CardDescription>
      </CardHeader>
      <CardContent className="flex flex-col gap-3">
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div className="max-w-[60ch]">
            <h3 className="font-heading text-sm font-medium">Delete key</h3>
            <p className="mt-1 text-sm text-muted-foreground">
              Every signature, verification, encryption and wrap request against{" "}
              <span className="font-heading text-foreground">{keyName}</span>{" "}
              starts failing immediately. It can be recovered from the
              deleted-keys tab until the retention window passes.
            </p>
          </div>
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
                  until the vault's retention window expires, after which they
                  are purged automatically.
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
        </div>
        {error && (
          <p role="alert" className="text-sm text-destructive">
            {error}
          </p>
        )}
      </CardContent>
    </Card>
  )
}
