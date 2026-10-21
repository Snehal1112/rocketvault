import { useState } from "react"
import { useMutation, useQueryClient } from "@tanstack/react-query"
import { UploadIcon } from "lucide-react"

import { restoreKey } from "@/api/keys"
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
 * Restores a key from a backup blob taken with <KeyBackupCard>. The blob is a
 * base64url envelope; it is passed through untouched rather than re-encoded,
 * since the backend decodes it with the exact encoding it wrote.
 */
export function KeyRestoreDialog({ vaultName }: { vaultName: string }) {
  const queryClient = useQueryClient()
  const [open, setOpen] = useState(false)
  const [blob, setBlob] = useState("")
  const [error, setError] = useState<string | null>(null)

  const restore = useMutation({
    mutationFn: (value: string) => restoreKey(vaultName, value),
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: ["keys", vaultName] })
      setOpen(false)
      setBlob("")
    },
    onError: (mutationError) =>
      setError(
        mutationError instanceof ApiError
          ? mutationError.message
          : "Failed to restore the key."
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
          <DialogTitle>Restore a key</DialogTitle>
          <DialogDescription>
            Recreates a key from a backup blob, including its version history.
          </DialogDescription>
        </DialogHeader>
        <form onSubmit={handleSubmit}>
          <FieldGroup>
            <Field>
              <FieldLabel htmlFor="key-restore-blob">Backup blob</FieldLabel>
              <FieldContent>
                <Textarea
                  id="key-restore-blob"
                  className="min-h-32 font-heading text-xs"
                  value={blob}
                  onChange={(event) => setBlob(event.target.value)}
                />
                <FieldDescription>
                  The value produced by this key's Backup card.
                </FieldDescription>
              </FieldContent>
            </Field>
            <Field>
              <FieldLabel htmlFor="key-restore-file">Load from file</FieldLabel>
              <FieldContent>
                <Input
                  id="key-restore-file"
                  type="file"
                  accept=".keybackup,.txt,text/plain"
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
