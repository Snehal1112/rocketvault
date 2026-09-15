import { useState } from "react"
import { useMutation, useQueryClient } from "@tanstack/react-query"
import { useNavigate } from "@tanstack/react-router"

import { deleteCertificate } from "@/api/certificates"
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
 * Soft-delete only. Purging happens from the deleted-certificates screen,
 * because the backend has no purge route for a live certificate -- it has to
 * be deleted first, and the two are granted by different data actions.
 */
export function CertificateDangerZone({
  vaultName,
  certificateId,
  certificateName,
}: {
  vaultName: string
  certificateId: string
  certificateName: string
}) {
  const navigate = useNavigate()
  const queryClient = useQueryClient()
  const [open, setOpen] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const remove = useMutation({
    mutationFn: () => deleteCertificate(vaultName, certificateId),
    onSuccess: async () => {
      setOpen(false)
      await queryClient.invalidateQueries({
        queryKey: ["certificates", vaultName],
      })
      navigate({
        to: "/vaults/$vaultName/certificates",
        params: { vaultName },
      })
    },
    onError: (mutationError) => {
      // Close the dialog so the error is readable and the rest of the page is
      // no longer inert behind a modal.
      setOpen(false)
      setError(
        mutationError instanceof ApiError
          ? mutationError.message
          : "Failed to delete the certificate."
      )
    },
  })

  return (
    <DangerZoneCard description="Deleting is reversible for as long as the vault's retention window lasts. Purging, from the deleted-certificates screen, is not.">
      <DangerAction
        title="Delete certificate"
        description={
          <>
            Anything presenting{" "}
            <span className="font-heading text-foreground">
              {certificateName}
            </span>{" "}
            keeps working — the certificate is already out in the world — but it
            can no longer be read, renewed or reissued from this vault. It stays
            recoverable until the retention window passes.
          </>
        }
        error={error}
      >
        <AlertDialog open={open} onOpenChange={setOpen}>
          <AlertDialogTrigger render={<Button variant="destructive" />}>
            Delete certificate
          </AlertDialogTrigger>
          <AlertDialogContent>
            <AlertDialogHeader>
              <AlertDialogTitle>Delete {certificateName}?</AlertDialogTitle>
              <AlertDialogDescription>
                The certificate and its policy leave this vault's active list
                immediately. They stay recoverable from the deleted-certificates
                screen until the vault's retention window expires, after which
                they are purged automatically.
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
