import { useState } from "react"
import { useMutation, useQueryClient } from "@tanstack/react-query"
import { useNavigate } from "@tanstack/react-router"
import { PlusIcon } from "lucide-react"

import { createVault } from "@/api/vaults"
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

/** Parses a "key=value, key2=value2" string into a tags map. Blank input
 * yields undefined (no tags sent) rather than an empty object. */
function parseTags(raw: string): Record<string, string> | undefined {
  const trimmed = raw.trim()
  if (!trimmed) {
    return undefined
  }

  const entries = trimmed
    .split(",")
    .map((pair) => pair.split("=").map((part) => part.trim()))
    .filter((pair): pair is [string, string] => Boolean(pair[0] && pair[1]))

  return entries.length > 0 ? Object.fromEntries(entries) : undefined
}

export function VaultCreateDialog() {
  const [open, setOpen] = useState(false)
  const [name, setName] = useState("")
  const [tags, setTags] = useState("")
  const [error, setError] = useState<string | null>(null)
  const queryClient = useQueryClient()
  const navigate = useNavigate()

  const mutation = useMutation({
    mutationFn: createVault,
    onSuccess: async (vault) => {
      await queryClient.invalidateQueries({ queryKey: ["vaults"] })
      setOpen(false)
      setName("")
      setTags("")
      navigate({
        to: "/vaults/$vaultName/secrets",
        params: { vaultName: vault.name },
      })
    },
    onError: (mutationError) => {
      setError(
        mutationError instanceof ApiError
          ? mutationError.message
          : "Failed to create vault."
      )
    },
  })

  function handleSubmit(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault()
    setError(null)
    mutation.mutate({ name, tags: parseTags(tags) })
  }

  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger render={<Button />}>
        <PlusIcon />
        Create vault
      </DialogTrigger>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Create a vault</DialogTitle>
          <DialogDescription>
            A new isolated security boundary with its own secrets, keys, and
            certificates.
          </DialogDescription>
        </DialogHeader>
        <form onSubmit={handleSubmit}>
          <FieldGroup>
            <Field>
              <FieldLabel htmlFor="vault-create-name">Name</FieldLabel>
              <FieldContent>
                <Input
                  id="vault-create-name"
                  value={name}
                  onChange={(event) => setName(event.target.value)}
                  required
                />
              </FieldContent>
            </Field>
            <Field>
              <FieldLabel htmlFor="vault-create-tags">
                Tags (optional)
              </FieldLabel>
              <FieldContent>
                <Input
                  id="vault-create-tags"
                  placeholder="env=prod, team=platform"
                  value={tags}
                  onChange={(event) => setTags(event.target.value)}
                />
                <FieldDescription>
                  Comma-separated key=value pairs.
                </FieldDescription>
              </FieldContent>
            </Field>
            {error && <FieldError>{error}</FieldError>}
          </FieldGroup>
          <DialogFooter className="mt-6">
            <Button type="submit" disabled={mutation.isPending}>
              {mutation.isPending ? "Creating…" : "Create"}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}
