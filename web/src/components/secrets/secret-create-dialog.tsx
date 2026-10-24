import { useState } from "react"
import { useMutation, useQueryClient } from "@tanstack/react-query"
import { useNavigate } from "@tanstack/react-router"
import { PlusIcon } from "lucide-react"

import {
  createSecret,
  generateSecret,
  type Secret,
  SECRET_CONTENT_TYPES,
} from "@/api/secrets"
import { ApiError } from "@/api/types"
import { validateSecretName } from "@/components/secrets/secret-name"
import { parseTagList, validateTagList } from "@/components/secrets/secret-tags"
import { Button } from "@/components/ui/button"
import { Checkbox } from "@/components/ui/checkbox"
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
import { NativeSelect, NativeSelectOption } from "@/components/ui/native-select"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { Textarea } from "@/components/ui/textarea"

// Backend generate limits (api/secrets.go:443-449).
const MIN_GENERATED_LENGTH = 8
const MAX_GENERATED_LENGTH = 128
const DEFAULT_GENERATED_LENGTH = 32

function describeError(error: unknown, fallback: string): string {
  return error instanceof ApiError ? error.message : fallback
}

/**
 * Two ways to put a secret in a vault, one dialog. Both tabs converge on the
 * same success handler: invalidate the list, then open the new secret's
 * detail page so the operator lands somewhere useful rather than back at a
 * list they have to scan.
 *
 * The "Generate" tab posts to the server's generate endpoint -- the value is
 * produced and stored by the backend. There is deliberately no client-side
 * password generator here; a value generated in the browser and then POSTed
 * would be a different, weaker thing wearing the same label.
 */
export function SecretCreateDialog({ vaultName }: { vaultName: string }) {
  const [open, setOpen] = useState(false)
  const queryClient = useQueryClient()
  const navigate = useNavigate()

  async function handleCreated(secret: Secret) {
    await queryClient.invalidateQueries({ queryKey: ["secrets", vaultName] })
    setOpen(false)
    navigate({
      to: "/vaults/$vaultName/secrets/$secretId",
      params: { vaultName, secretId: secret.id },
    })
  }

  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger render={<Button />}>
        <PlusIcon />
        Create secret
      </DialogTrigger>
      <DialogContent className="sm:max-w-lg">
        <DialogHeader>
          <DialogTitle>Create a secret</DialogTitle>
          <DialogDescription>
            Store a value you already have, or have the server generate one.
          </DialogDescription>
        </DialogHeader>
        <Tabs defaultValue="manual">
          <TabsList className="mb-4">
            <TabsTrigger value="manual">Manual value</TabsTrigger>
            <TabsTrigger value="generate">Generate</TabsTrigger>
          </TabsList>
          <TabsContent value="manual">
            <ManualSecretForm vaultName={vaultName} onCreated={handleCreated} />
          </TabsContent>
          <TabsContent value="generate">
            <GenerateSecretForm
              vaultName={vaultName}
              onCreated={handleCreated}
            />
          </TabsContent>
        </Tabs>
      </DialogContent>
    </Dialog>
  )
}

function ManualSecretForm({
  vaultName,
  onCreated,
}: {
  vaultName: string
  onCreated: (secret: Secret) => void | Promise<void>
}) {
  const [name, setName] = useState("")
  const [value, setValue] = useState("")
  const [contentType, setContentType] = useState("")
  const [tags, setTags] = useState("")
  const [error, setError] = useState<string | null>(null)

  const mutation = useMutation({
    mutationFn: (input: Parameters<typeof createSecret>[1]) =>
      createSecret(vaultName, input),
    onSuccess: onCreated,
    onError: (mutationError) => {
      setError(describeError(mutationError, "Failed to create secret."))
    },
  })

  function handleSubmit(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault()

    const nameError = validateSecretName(name)
    if (nameError) {
      setError(nameError)
      return
    }
    if (!value) {
      setError("Value is required.")
      return
    }
    const parsedTags = parseTagList(tags)
    const tagError = validateTagList(parsedTags)
    if (tagError) {
      setError(tagError)
      return
    }

    setError(null)
    mutation.mutate({
      name: name.trim(),
      value,
      tags: parsedTags,
      contentType: contentType || undefined,
    })
  }

  return (
    <form onSubmit={handleSubmit}>
      <FieldGroup>
        <Field>
          <FieldLabel htmlFor="secret-create-name">Name</FieldLabel>
          <FieldContent>
            <Input
              id="secret-create-name"
              value={name}
              onChange={(event) => setName(event.target.value)}
              placeholder="db-password"
              className="font-heading"
            />
            <FieldDescription>
              Letters, numbers, and hyphens. Must start with a letter.
            </FieldDescription>
          </FieldContent>
        </Field>
        <Field>
          <FieldLabel htmlFor="secret-create-value">Value</FieldLabel>
          <FieldContent>
            <Textarea
              id="secret-create-value"
              value={value}
              onChange={(event) => setValue(event.target.value)}
              rows={3}
              className="font-heading"
            />
          </FieldContent>
        </Field>
        <Field>
          <FieldLabel htmlFor="secret-create-content-type">
            Content type
          </FieldLabel>
          <FieldContent>
            <NativeSelect
              className="w-full"
              id="secret-create-content-type"
              value={contentType}
              onChange={(event) => setContentType(event.target.value)}
            >
              {SECRET_CONTENT_TYPES.map((type) => (
                <NativeSelectOption key={type.value} value={type.value}>
                  {type.label}
                </NativeSelectOption>
              ))}
            </NativeSelect>
            <FieldDescription>
              A hint for whoever consumes this value. It is not enforced.
            </FieldDescription>
          </FieldContent>
        </Field>
        <Field>
          <FieldLabel htmlFor="secret-create-tags">Tags</FieldLabel>
          <FieldContent>
            <Input
              id="secret-create-tags"
              value={tags}
              onChange={(event) => setTags(event.target.value)}
              placeholder="env=prod, team=platform"
            />
            <FieldDescription>Comma-separated, up to 15.</FieldDescription>
          </FieldContent>
        </Field>
        {error && <FieldError>{error}</FieldError>}
      </FieldGroup>
      <DialogFooter className="mt-6">
        <Button type="submit" disabled={mutation.isPending}>
          {mutation.isPending ? "Creating…" : "Create secret"}
        </Button>
      </DialogFooter>
    </form>
  )
}

function GenerateSecretForm({
  vaultName,
  onCreated,
}: {
  vaultName: string
  onCreated: (secret: Secret) => void | Promise<void>
}) {
  const [name, setName] = useState("")
  const [length, setLength] = useState(String(DEFAULT_GENERATED_LENGTH))
  const [useLowercase, setUseLowercase] = useState(true)
  const [useUppercase, setUseUppercase] = useState(true)
  const [useNumbers, setUseNumbers] = useState(true)
  const [useSymbols, setUseSymbols] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const mutation = useMutation({
    mutationFn: (input: Parameters<typeof generateSecret>[1]) =>
      generateSecret(vaultName, input),
    onSuccess: onCreated,
    onError: (mutationError) => {
      setError(describeError(mutationError, "Failed to generate secret."))
    },
  })

  function handleSubmit(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault()

    const nameError = validateSecretName(name)
    if (nameError) {
      setError(nameError)
      return
    }
    const parsedLength = Number(length)
    if (
      !Number.isInteger(parsedLength) ||
      parsedLength < MIN_GENERATED_LENGTH ||
      parsedLength > MAX_GENERATED_LENGTH
    ) {
      setError(
        `Length must be between ${MIN_GENERATED_LENGTH} and ${MAX_GENERATED_LENGTH}.`
      )
      return
    }
    if (!useLowercase && !useUppercase && !useNumbers && !useSymbols) {
      setError("Pick at least one character set.")
      return
    }

    setError(null)
    mutation.mutate({
      name: name.trim(),
      length: parsedLength,
      useLowercase,
      useUppercase,
      useNumbers,
      useSymbols,
    })
  }

  return (
    <form onSubmit={handleSubmit}>
      <FieldGroup>
        <Field>
          <FieldLabel htmlFor="secret-generate-name">Name</FieldLabel>
          <FieldContent>
            <Input
              id="secret-generate-name"
              value={name}
              onChange={(event) => setName(event.target.value)}
              placeholder="api-token"
              className="font-heading"
            />
          </FieldContent>
        </Field>
        <Field>
          <FieldLabel htmlFor="secret-generate-length">Length</FieldLabel>
          <FieldContent>
            <Input
              id="secret-generate-length"
              type="number"
              min={MIN_GENERATED_LENGTH}
              max={MAX_GENERATED_LENGTH}
              value={length}
              onChange={(event) => setLength(event.target.value)}
            />
            <FieldDescription>
              Between {MIN_GENERATED_LENGTH} and {MAX_GENERATED_LENGTH}{" "}
              characters.
            </FieldDescription>
          </FieldContent>
        </Field>
        <Field>
          <FieldLabel>Character sets</FieldLabel>
          <FieldContent className="gap-3">
            <CharacterSetToggle
              id="secret-generate-lowercase"
              label="Lowercase (a-z)"
              checked={useLowercase}
              onCheckedChange={setUseLowercase}
            />
            <CharacterSetToggle
              id="secret-generate-uppercase"
              label="Uppercase (A-Z)"
              checked={useUppercase}
              onCheckedChange={setUseUppercase}
            />
            <CharacterSetToggle
              id="secret-generate-numbers"
              label="Numbers (0-9)"
              checked={useNumbers}
              onCheckedChange={setUseNumbers}
            />
            <CharacterSetToggle
              id="secret-generate-symbols"
              label="Symbols (!@#…)"
              checked={useSymbols}
              onCheckedChange={setUseSymbols}
            />
          </FieldContent>
        </Field>
        <FieldDescription>
          The value is generated on the server and stored immediately. You can
          reveal it on the next screen.
        </FieldDescription>
        {error && <FieldError>{error}</FieldError>}
      </FieldGroup>
      <DialogFooter className="mt-6">
        <Button type="submit" disabled={mutation.isPending}>
          {mutation.isPending ? "Generating…" : "Generate secret"}
        </Button>
      </DialogFooter>
    </form>
  )
}

function CharacterSetToggle({
  id,
  label,
  checked,
  onCheckedChange,
}: {
  id: string
  label: string
  checked: boolean
  onCheckedChange: (checked: boolean) => void
}) {
  return (
    <div className="flex items-center gap-2.5">
      <Checkbox id={id} checked={checked} onCheckedChange={onCheckedChange} />
      <label htmlFor={id} className="text-sm">
        {label}
      </label>
    </div>
  )
}
