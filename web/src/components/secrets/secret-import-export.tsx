import { useState } from "react"
import { useMutation, useQueryClient } from "@tanstack/react-query"
import { ArrowRightLeftIcon } from "lucide-react"

import {
  exportSecrets,
  type ImportResult,
  importSecrets,
  restoreSecret,
  type TransferFormat,
} from "@/api/secrets"
import { ApiError } from "@/api/types"
import { downloadBlob } from "@/components/secrets/download"
import { Button } from "@/components/ui/button"
import { Checkbox } from "@/components/ui/checkbox"
import {
  Dialog,
  DialogContent,
  DialogDescription,
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
import { NativeSelect, NativeSelectOption } from "@/components/ui/native-select"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { Textarea } from "@/components/ui/textarea"

function describeError(error: unknown, fallback: string): string {
  return error instanceof ApiError ? error.message : fallback
}

/** Bulk movement of secrets into and out of a vault, plus single-secret
 * restore from a backup blob -- all three are vault-scoped, so they live
 * together on the list screen rather than on any one secret. */
export function SecretTransferDialog({ vaultName }: { vaultName: string }) {
  const [open, setOpen] = useState(false)

  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger render={<Button variant="outline" />}>
        <ArrowRightLeftIcon />
        Import / export
      </DialogTrigger>
      <DialogContent className="sm:max-w-lg">
        <DialogHeader>
          <DialogTitle>Move secrets in and out</DialogTitle>
          <DialogDescription>
            Bulk export and import for this vault, plus restore from a
            single-secret backup.
          </DialogDescription>
        </DialogHeader>
        <Tabs defaultValue="export">
          <TabsList className="mb-4">
            <TabsTrigger value="export">Export</TabsTrigger>
            <TabsTrigger value="import">Import</TabsTrigger>
            <TabsTrigger value="restore">Restore</TabsTrigger>
          </TabsList>
          <TabsContent value="export">
            <ExportPanel vaultName={vaultName} />
          </TabsContent>
          <TabsContent value="import">
            <ImportPanel vaultName={vaultName} />
          </TabsContent>
          <TabsContent value="restore">
            <RestorePanel vaultName={vaultName} />
          </TabsContent>
        </Tabs>
      </DialogContent>
    </Dialog>
  )
}

function FormatSelect({
  id,
  value,
  onChange,
}: {
  id: string
  value: TransferFormat
  onChange: (format: TransferFormat) => void
}) {
  return (
    <NativeSelect
      className="w-full"
      id={id}
      value={value}
      onChange={(event) => onChange(event.target.value as TransferFormat)}
    >
      <NativeSelectOption value="json">JSON</NativeSelectOption>
      <NativeSelectOption value="csv">CSV</NativeSelectOption>
    </NativeSelect>
  )
}

function ExportPanel({ vaultName }: { vaultName: string }) {
  const [format, setFormat] = useState<TransferFormat>("json")
  const [includeTags, setIncludeTags] = useState(true)
  const [encrypt, setEncrypt] = useState(false)
  const [passphrase, setPassphrase] = useState("")
  const [error, setError] = useState<string | null>(null)

  const mutation = useMutation({
    mutationFn: () =>
      exportSecrets(vaultName, {
        format,
        includeTags,
        encrypt,
        passphrase: encrypt ? passphrase : undefined,
      }),
    onSuccess: (result) => {
      setError(null)
      downloadBlob(result.blob, result.filename)
    },
    onError: (mutationError) => {
      setError(describeError(mutationError, "Failed to export secrets."))
    },
  })

  function handleSubmit(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault()
    // The backend requires a passphrase whenever encrypt is set
    // (internal/services/secrets/secret_service.go:695-700); catching it
    // here saves a round trip that would only 400.
    if (encrypt && !passphrase) {
      setError("A passphrase is required to seal the export.")
      return
    }
    setError(null)
    mutation.mutate()
  }

  return (
    <form onSubmit={handleSubmit}>
      <FieldGroup>
        <Field>
          <FieldLabel htmlFor="secret-export-format">Format</FieldLabel>
          <FieldContent>
            <FormatSelect
              id="secret-export-format"
              value={format}
              onChange={setFormat}
            />
          </FieldContent>
        </Field>
        <div className="flex items-center gap-2.5">
          <Checkbox
            id="secret-export-tags"
            checked={includeTags}
            onCheckedChange={setIncludeTags}
          />
          <label htmlFor="secret-export-tags" className="text-sm">
            Include tags
          </label>
        </div>
        <div className="flex items-center gap-2.5">
          <Checkbox
            id="secret-export-encrypt"
            checked={encrypt}
            onCheckedChange={setEncrypt}
          />
          <label htmlFor="secret-export-encrypt" className="text-sm">
            Seal with a passphrase
          </label>
        </div>
        {encrypt && (
          <Field>
            <FieldLabel htmlFor="secret-export-passphrase">
              Passphrase
            </FieldLabel>
            <FieldContent>
              <Input
                id="secret-export-passphrase"
                type="password"
                value={passphrase}
                onChange={(event) => setPassphrase(event.target.value)}
              />
            </FieldContent>
          </Field>
        )}
        <FieldDescription>
          An unsealed export is plain text — every value in this vault, readable
          by anything that can open the file.
        </FieldDescription>
        {error && <FieldError>{error}</FieldError>}
        <Button type="submit" disabled={mutation.isPending}>
          {mutation.isPending ? "Exporting…" : "Export secrets"}
        </Button>
      </FieldGroup>
    </form>
  )
}

function ImportPanel({ vaultName }: { vaultName: string }) {
  const queryClient = useQueryClient()
  const [file, setFile] = useState<File | null>(null)
  const [format, setFormat] = useState<TransferFormat>("json")
  const [overwrite, setOverwrite] = useState(false)
  const [passphrase, setPassphrase] = useState("")
  const [error, setError] = useState<string | null>(null)
  const [result, setResult] = useState<ImportResult | null>(null)

  const mutation = useMutation({
    mutationFn: () =>
      importSecrets(vaultName, {
        file: file as File,
        format,
        overwrite,
        passphrase: passphrase || undefined,
      }),
    onSuccess: async (importResult) => {
      setError(null)
      setResult(importResult)
      await queryClient.invalidateQueries({ queryKey: ["secrets", vaultName] })
    },
    onError: (mutationError) => {
      setResult(null)
      setError(describeError(mutationError, "Failed to import secrets."))
    },
  })

  function handleSubmit(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (!file) {
      setError("Choose a file to import.")
      return
    }
    setError(null)
    mutation.mutate()
  }

  const shortfall = result ? result.totalCount - result.importedCount : 0

  return (
    <form onSubmit={handleSubmit}>
      <FieldGroup>
        <Field>
          <FieldLabel htmlFor="secret-import-file">File</FieldLabel>
          <FieldContent>
            <Input
              id="secret-import-file"
              type="file"
              accept=".json,.csv,application/json,text/csv"
              onChange={(event) => setFile(event.target.files?.[0] ?? null)}
            />
          </FieldContent>
        </Field>
        <Field>
          <FieldLabel htmlFor="secret-import-format">Format</FieldLabel>
          <FieldContent>
            <FormatSelect
              id="secret-import-format"
              value={format}
              onChange={setFormat}
            />
          </FieldContent>
        </Field>
        <div className="flex items-center gap-2.5">
          <Checkbox
            id="secret-import-overwrite"
            checked={overwrite}
            onCheckedChange={setOverwrite}
          />
          <label htmlFor="secret-import-overwrite" className="text-sm">
            Overwrite secrets that already exist
          </label>
        </div>
        <Field>
          <FieldLabel htmlFor="secret-import-passphrase">
            Passphrase (sealed exports only)
          </FieldLabel>
          <FieldContent>
            <Input
              id="secret-import-passphrase"
              type="password"
              value={passphrase}
              onChange={(event) => setPassphrase(event.target.value)}
            />
          </FieldContent>
        </Field>
        {error && <FieldError>{error}</FieldError>}
        {result && (
          <div role="status" className="flex flex-col gap-1 text-sm">
            <p className="text-success">
              Imported{" "}
              <span className="font-heading">
                {result.importedCount}/{result.totalCount}
              </span>{" "}
              secrets.
            </p>
            {shortfall > 0 && (
              // BACKEND GAP: the service layer computes per-record errors
              // (secrets.ImportResult carries SkippedCount, FailedCount and
              // an Errors []string) but api/secrets_transfer.go:172-179
              // drops all three, so the UI genuinely cannot name the rows
              // that did not land. Saying which rows failed would mean
              // inventing them.
              <p className="text-muted-foreground">
                {shortfall} {shortfall === 1 ? "row" : "rows"} did not import.
                The API does not report which, or whether they were skipped as
                duplicates or rejected — compare the file against the list to
                find them.
              </p>
            )}
          </div>
        )}
        <Button type="submit" disabled={mutation.isPending}>
          {mutation.isPending ? "Importing…" : "Import secrets"}
        </Button>
      </FieldGroup>
    </form>
  )
}

function RestorePanel({ vaultName }: { vaultName: string }) {
  const queryClient = useQueryClient()
  const [blob, setBlob] = useState("")
  const [error, setError] = useState<string | null>(null)
  const [restored, setRestored] = useState(false)

  const mutation = useMutation({
    mutationFn: () => restoreSecret(vaultName, blob.trim()),
    onSuccess: async () => {
      setError(null)
      setRestored(true)
      setBlob("")
      await queryClient.invalidateQueries({ queryKey: ["secrets", vaultName] })
    },
    onError: (mutationError) => {
      setRestored(false)
      setError(describeError(mutationError, "Failed to restore secret."))
    },
  })

  async function handleFile(file: File | null) {
    if (!file) {
      return
    }
    setBlob((await file.text()).trim())
  }

  function handleSubmit(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (!blob.trim()) {
      setError("Paste a backup blob, or choose a backup file.")
      return
    }
    setError(null)
    mutation.mutate()
  }

  return (
    <form onSubmit={handleSubmit}>
      <FieldGroup>
        <Field>
          <FieldLabel htmlFor="secret-restore-file">Backup file</FieldLabel>
          <FieldContent>
            <Input
              id="secret-restore-file"
              type="file"
              accept=".txt,text/plain"
              onChange={(event) => handleFile(event.target.files?.[0] ?? null)}
            />
          </FieldContent>
        </Field>
        <Field>
          <FieldLabel htmlFor="secret-restore-blob">Backup blob</FieldLabel>
          <FieldContent>
            <Textarea
              id="secret-restore-blob"
              rows={4}
              value={blob}
              onChange={(event) => setBlob(event.target.value)}
              placeholder="Paste the base64 blob from a secret backup"
              className="font-heading"
            />
            <FieldDescription>
              The secret is restored into{" "}
              <span className="font-heading text-foreground">{vaultName}</span>{" "}
              under a new id, whichever vault it was taken from.
            </FieldDescription>
          </FieldContent>
        </Field>
        {error && <FieldError>{error}</FieldError>}
        {restored && (
          <p role="status" className="text-sm text-success">
            Secret restored. It appears in the list under a new id.
          </p>
        )}
        <Button type="submit" disabled={mutation.isPending}>
          {mutation.isPending ? "Restoring…" : "Restore secret"}
        </Button>
      </FieldGroup>
    </form>
  )
}
