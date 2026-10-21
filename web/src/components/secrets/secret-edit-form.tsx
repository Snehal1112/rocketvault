import { useEffect, useState } from "react"
import { useMutation, useQueryClient } from "@tanstack/react-query"

import {
  type Secret,
  SECRET_CONTENT_TYPES,
  type UpdateSecretInput,
  updateSecret,
} from "@/api/secrets"
import { ApiError } from "@/api/types"
import { validateSecretName } from "@/components/secrets/secret-name"
import {
  formatTagList,
  parseTagList,
  validateTagList,
} from "@/components/secrets/secret-tags"
import { Button } from "@/components/ui/button"
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
import { Switch } from "@/components/ui/switch"
import { Textarea } from "@/components/ui/textarea"

function sameTags(left: string[], right: string[]): boolean {
  return (
    left.length === right.length && left.every((tag, i) => tag === right[i])
  )
}

/**
 * Edits the properties of an existing secret.
 *
 * Two backend behaviours drive the shape of this form
 * (model/secret.go:205-215):
 *
 *  - `name` and `value` are plain strings in UpdateSecretRequest, so an
 *    empty string reads as "unchanged". Neither can be cleared, and the
 *    value field is therefore a "set a new value" box, left blank to keep
 *    the current one -- it never pre-fills with the existing plaintext.
 *  - A request that changes nothing is a 400, so the submit button stays
 *    disabled until something actually differs.
 */
export function SecretEditForm({
  vaultName,
  secret,
}: {
  vaultName: string
  secret: Secret
}) {
  const queryClient = useQueryClient()
  const [name, setName] = useState(secret.name)
  const [newValue, setNewValue] = useState("")
  const [contentType, setContentType] = useState(secret.contentType ?? "")
  const [tags, setTags] = useState(formatTagList(secret.tags))
  const [enabled, setEnabled] = useState(secret.enabled)
  const [error, setError] = useState<string | null>(null)
  const [saved, setSaved] = useState(false)

  useEffect(() => {
    setName(secret.name)
    setNewValue("")
    setContentType(secret.contentType ?? "")
    setTags(formatTagList(secret.tags))
    setEnabled(secret.enabled)
  }, [secret])

  const mutation = useMutation({
    mutationFn: (patch: UpdateSecretInput) =>
      updateSecret(vaultName, secret.id, patch),
    onSuccess: async () => {
      setError(null)
      setSaved(true)
      setNewValue("")
      await queryClient.invalidateQueries({ queryKey: ["secrets", vaultName] })
    },
    onError: (mutationError) => {
      setSaved(false)
      setError(
        mutationError instanceof ApiError
          ? mutationError.message
          : "Failed to update secret."
      )
    },
  })

  function buildPatch(): UpdateSecretInput {
    const patch: UpdateSecretInput = {}
    const trimmedName = name.trim()
    if (trimmedName && trimmedName !== secret.name) {
      patch.name = trimmedName
    }
    if (newValue) {
      patch.value = newValue
    }
    if (contentType !== (secret.contentType ?? "")) {
      patch.contentType = contentType
    }
    if (enabled !== secret.enabled) {
      patch.enabled = enabled
    }
    const parsedTags = parseTagList(tags) ?? []
    if (!sameTags(parsedTags, secret.tags ?? [])) {
      patch.tags = parsedTags
    }
    return patch
  }

  const patch = buildPatch()
  const hasChanges = Object.keys(patch).length > 0

  function handleSubmit(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault()
    setSaved(false)

    if (patch.name !== undefined) {
      const nameError = validateSecretName(patch.name)
      if (nameError) {
        setError(nameError)
        return
      }
    }
    const tagError = validateTagList(patch.tags)
    if (tagError) {
      setError(tagError)
      return
    }

    setError(null)
    mutation.mutate(patch)
  }

  return (
    <form onSubmit={handleSubmit}>
      <FieldGroup>
        <Field>
          <FieldLabel htmlFor="secret-edit-name">Name</FieldLabel>
          <FieldContent>
            <Input
              id="secret-edit-name"
              value={name}
              onChange={(event) => setName(event.target.value)}
              className="font-heading"
            />
          </FieldContent>
        </Field>
        <Field>
          <FieldLabel htmlFor="secret-edit-value">New value</FieldLabel>
          <FieldContent>
            <Textarea
              id="secret-edit-value"
              value={newValue}
              onChange={(event) => setNewValue(event.target.value)}
              rows={3}
              placeholder="Leave blank to keep the current value"
              className="font-heading"
            />
            <FieldDescription>
              Saving a new value creates version {secret.version + 1}. The
              current value stays readable in the version history.
            </FieldDescription>
          </FieldContent>
        </Field>
        <Field>
          <FieldLabel htmlFor="secret-edit-content-type">
            Content type
          </FieldLabel>
          <FieldContent>
            <NativeSelect
              className="w-full"
              id="secret-edit-content-type"
              value={contentType}
              onChange={(event) => setContentType(event.target.value)}
            >
              {SECRET_CONTENT_TYPES.map((type) => (
                <NativeSelectOption key={type.value} value={type.value}>
                  {type.label}
                </NativeSelectOption>
              ))}
            </NativeSelect>
          </FieldContent>
        </Field>
        <Field>
          <FieldLabel htmlFor="secret-edit-tags">Tags</FieldLabel>
          <FieldContent>
            <Input
              id="secret-edit-tags"
              value={tags}
              onChange={(event) => setTags(event.target.value)}
              placeholder="env=prod, team=platform"
            />
            <FieldDescription>
              Comma-separated. Saving replaces the whole set.
            </FieldDescription>
          </FieldContent>
        </Field>
        <Field orientation="horizontal">
          <FieldContent>
            <FieldLabel htmlFor="secret-edit-enabled">Enabled</FieldLabel>
            <FieldDescription>
              A disabled secret stays stored but stops answering reads.
            </FieldDescription>
          </FieldContent>
          <Switch
            id="secret-edit-enabled"
            checked={enabled}
            onCheckedChange={setEnabled}
          />
        </Field>
        {error && <FieldError>{error}</FieldError>}
        {saved && !error && (
          <p className="text-sm text-success">Secret updated.</p>
        )}
        <Button type="submit" disabled={!hasChanges || mutation.isPending}>
          {mutation.isPending ? "Saving…" : "Save changes"}
        </Button>
      </FieldGroup>
    </form>
  )
}
