import { useState } from "react"
import { useMutation, useQueryClient } from "@tanstack/react-query"
import { UploadIcon } from "lucide-react"

import { restoreCertificate } from "@/api/certificates"
import { ApiError } from "@/api/types"
import { Button } from "@/components/ui/button"
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog"
import {
  Field,
  FieldContent,
  FieldDescription,
  FieldError,
  FieldGroup,
  FieldLabel,
} from "@/components/ui/field"
import { Input } from "@/components/ui/input"
import { Textarea } from "@/components/ui/textarea"

/**
 * Restores a certificate from a blob taken with <CertificateBackupCard>.
 *
 * A blob the server cannot decode comes back as a 400 on "blob". That is a
 * problem with the pasted value, so it is reported inside the dialog next to
 * the control that produced it -- closing the dialog to show a page-level
 * banner would throw away the very input the operator needs to correct.
 */
export function CertificateRestoreDialog({ vaultName }: { vaultName: string }) {
  const queryClient = useQueryClient()
  const [open, setOpen] = useState(false)
  const [blob, setBlob] = useState("")
  const [error, setError] = useState<string | null>(null)

  const restore = useMutation({
    mutationFn: (value: string) => restoreCertificate(vaultName, value),
    onSuccess: async () => {
      await queryClient.invalidateQueries({
        queryKey: ["certificates", vaultName],
      })
      setOpen(false)
      setBlob("")
    },
    onError: (mutationError) =>
      setError(
        mutationError instanceof ApiError
          ? mutationError.message
          : "Failed to restore the certificate."
      ),
  })

  async function handleFile(event: React.ChangeEvent<HTMLInputElement>) {
    const file = event.target.files?.[0]
    if (file) {
      setBlob((await file.text()).trim())
    }
  }

  function handleSubmit(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault()
    const trimmed = blob.trim()
    if (!trimmed) {
      setError("Paste a backup blob, or load one from a file.")
      return
    }
    setError(null)
    restore.mutate(trimmed)
  }

  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger render={<Button variant="outline" />}>
        <UploadIcon />
        Restore from backup
      </DialogTrigger>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Restore a certificate</DialogTitle>
          <DialogDescription>
            Recreates a certificate from a backup blob. This is not a PEM import
            — only a blob produced by a certificate Backup card is accepted.
          </DialogDescription>
        </DialogHeader>
        <form onSubmit={handleSubmit}>
          <FieldGroup>
            <Field>
              <FieldLabel htmlFor="cert-restore-blob">Backup blob</FieldLabel>
              <FieldContent>
                <Textarea
                  id="cert-restore-blob"
                  className="min-h-32 font-heading text-xs"
                  value={blob}
                  onChange={(event) => setBlob(event.target.value)}
                />
                <FieldDescription>
                  The value produced by a certificate's Backup card.
                </FieldDescription>
              </FieldContent>
            </Field>
            <Field>
              <FieldLabel htmlFor="cert-restore-file">
                Load from file
              </FieldLabel>
              <FieldContent>
                <Input
                  id="cert-restore-file"
                  type="file"
                  accept=".certbackup,.txt,text/plain"
                  onChange={handleFile}
                />
              </FieldContent>
            </Field>
            {error && <FieldError>{error}</FieldError>}
          </FieldGroup>
          <DialogFooter className="mt-6">
            <Button type="submit" disabled={restore.isPending}>
              {restore.isPending ? "Restoring…" : "Restore"}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}
