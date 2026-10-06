import { useState } from "react"
import { useMutation, useQueryClient } from "@tanstack/react-query"
import { useNavigate } from "@tanstack/react-router"

import { ApiError } from "@/api/types"
import { deleteVault, purgeVault } from "@/api/vaults"
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
import { Separator } from "@/components/ui/separator"

// The backend never lets the default vault be deleted (it always refuses
// with a 400) -- disabling the button here is a UX nicety, not the actual
// enforcement boundary.
const DEFAULT_VAULT_NAME = "default"

/**
 * Delete and purge are gated by DIFFERENT permissions on the backend --
 * delete uses CanManageVault, purge uses a distinct vault data-action
 * (ActionVaultPurge, effectively a Purge Operator/Administrator role on
 * this specific vault). Each action attempts its own call and surfaces its
 * own 403 independently; holding (or lacking) one permission must never
 * hide or disable the other's button.
 */
export function VaultDangerZone({ vaultName }: { vaultName: string }) {
  const navigate = useNavigate()
  const queryClient = useQueryClient()
  const [deleteOpen, setDeleteOpen] = useState(false)
  const [purgeOpen, setPurgeOpen] = useState(false)
  const [deleteError, setDeleteError] = useState<string | null>(null)
  const [purgeError, setPurgeError] = useState<string | null>(null)
  const isDefaultVault = vaultName === DEFAULT_VAULT_NAME

  const deleteMutation = useMutation({
    mutationFn: () => deleteVault(vaultName),
    onSuccess: async () => {
      setDeleteOpen(false)
      await queryClient.invalidateQueries({ queryKey: ["vaults"] })
      navigate({ to: "/vaults" })
    },
    onError: (mutationError) => {
      // Close the confirmation dialog so the error is visible (and the
      // rest of the page, including the purge button, is no longer inert
      // behind the modal) instead of leaving the dialog open indefinitely.
      setDeleteOpen(false)
      setDeleteError(
        mutationError instanceof ApiError && mutationError.statusCode === 403
          ? "You don't have permission to delete this vault."
          : "Failed to delete vault."
      )
    },
  })

  const purgeMutation = useMutation({
    mutationFn: () => purgeVault(vaultName),
    onSuccess: async () => {
      setPurgeOpen(false)
      await queryClient.invalidateQueries({ queryKey: ["vaults"] })
      navigate({ to: "/vaults" })
    },
    onError: (mutationError) => {
      setPurgeOpen(false)
      setPurgeError(
        mutationError instanceof ApiError && mutationError.statusCode === 403
          ? "You don't have permission to purge this vault."
          : "Failed to purge vault."
      )
    },
  })

  return (
    <DangerZoneCard description="Delete and purge are granted separately — holding one does not imply the other.">
      <DangerAction
        title="Delete vault"
        description={
          <>
            Soft-deletes{" "}
            <span className="font-heading text-foreground">{vaultName}</span>{" "}
            and everything in it. An administrator can recover it within the
            retention window; after that it is purged automatically.
            {isDefaultVault &&
              " The default vault cannot be deleted, so this is disabled."}
          </>
        }
        error={deleteError}
      >
        <AlertDialog open={deleteOpen} onOpenChange={setDeleteOpen}>
          <AlertDialogTrigger
            render={<Button variant="destructive" disabled={isDefaultVault} />}
          >
            Delete vault
          </AlertDialogTrigger>
          <AlertDialogContent>
            <AlertDialogHeader>
              <AlertDialogTitle>Delete {vaultName}?</AlertDialogTitle>
              <AlertDialogDescription>
                Every secret, key, and certificate in this vault stops answering
                immediately. An administrator can recover it within the
                retention window; once that window passes it is purged
                automatically and cannot be brought back.
              </AlertDialogDescription>
            </AlertDialogHeader>
            <AlertDialogFooter>
              <AlertDialogCancel>Cancel</AlertDialogCancel>
              <AlertDialogAction
                render={<Button variant="destructive" />}
                onClick={() => deleteMutation.mutate()}
              >
                Confirm
              </AlertDialogAction>
            </AlertDialogFooter>
          </AlertDialogContent>
        </AlertDialog>
      </DangerAction>

      <Separator className="bg-destructive/20" />

      <DangerAction
        title="Purge vault"
        description={
          <>
            Permanently destroys{" "}
            <span className="font-heading text-foreground">{vaultName}</span>{" "}
            and every secret, key, and certificate in it. This cannot be undone.
            Requires a Purge Operator or Purge Administrator role on this vault.
          </>
        }
        error={purgeError}
      >
        <AlertDialog open={purgeOpen} onOpenChange={setPurgeOpen}>
          <AlertDialogTrigger render={<Button variant="destructive" />}>
            Purge vault
          </AlertDialogTrigger>
          <AlertDialogContent>
            <AlertDialogHeader>
              <AlertDialogTitle>
                Permanently purge {vaultName}?
              </AlertDialogTitle>
              <AlertDialogDescription>
                This destroys the vault and every secret, key, and certificate
                in it outright. There is no recovery window and no backup taken
                on your behalf — this cannot be undone.
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
      </DangerAction>
    </DangerZoneCard>
  )
}
