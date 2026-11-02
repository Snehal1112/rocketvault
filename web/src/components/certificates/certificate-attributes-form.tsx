import { useState } from "react"
import { useMutation, useQueryClient } from "@tanstack/react-query"

import {
  type Certificate,
  updateCertificate,
  type UpdateCertificateInput,
} from "@/api/certificates"
import { ApiError } from "@/api/types"
import { Button } from "@/components/ui/button"
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card"
import {
  Field,
  FieldContent,
  FieldDescription,
  FieldError,
  FieldGroup,
  FieldLabel,
} from "@/components/ui/field"
import { Input } from "@/components/ui/input"
import { Separator } from "@/components/ui/separator"
import { Switch } from "@/components/ui/switch"
import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@/components/ui/tooltip"

/** Tags are a plain string array on the wire, edited here as one
 * comma-separated field -- the same shape the issue dialog uses. */
function parseTags(raw: string): string[] {
  return raw
    .split(",")
    .map((tag) => tag.trim())
    .filter(Boolean)
}

function sameTags(left: string[], right: string[]): boolean {
  return (
    left.length === right.length && left.every((tag, i) => tag === right[i])
  )
}

/** An ISO instant as the value a <input type="datetime-local"> wants. */
function toLocalInput(iso: string | undefined): string {
  if (!iso) {
    return ""
  }
  const parsed = new Date(iso)
  return Number.isNaN(parsed.getTime()) ? "" : parsed.toISOString().slice(0, 16)
}

/**
 * Edits the attributes PUT actually accepts.
 *
 * `enabled` saves on change rather than behind the Save button, matching the
 * keys detail page: an operator disabling a mis-issued certificate wants it
 * off now. Everything else is a normal edit-then-save form, because renaming
 * a certificate halfway through typing would be worse than useless.
 */
export function CertificateAttributesForm({
  vaultName,
  certificate,
}: {
  vaultName: string
  certificate: Certificate
}) {
  const queryClient = useQueryClient()

  const [name, setName] = useState(certificate.name)
  const [tags, setTags] = useState(certificate.tags.join(", "))
  const [notBefore, setNotBefore] = useState(
    toLocalInput(certificate.notBefore)
  )
  // Tri-state on purpose: null means "the operator has not touched this".
  // No response reports the stored purge_protection, so there is no current
  // value to show -- see the field's own description.
  const [purgeProtection, setPurgeProtection] = useState<boolean | null>(null)
  const [error, setError] = useState<string | null>(null)

  const save = useMutation({
    mutationFn: (patch: UpdateCertificateInput) =>
      updateCertificate(vaultName, certificate.id, patch),
    onSuccess: async () => {
      setError(null)
      await queryClient.invalidateQueries({
        queryKey: ["certificates", vaultName],
      })
    },
    onError: (mutationError) =>
      setError(
        mutationError instanceof ApiError
          ? mutationError.message
          : "Failed to update the certificate."
      ),
  })

  function handleSubmit(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault()

    // Built field by field so an untouched attribute is absent from the body
    // rather than resent: the backend rejects a body with every field unset
    // with a 400, and resending an unchanged value would silently overwrite
    // whatever a concurrent editor had just written.
    const patch: UpdateCertificateInput = {}
    if (name !== certificate.name) {
      patch.name = name
    }
    const nextTags = parseTags(tags)
    if (!sameTags(nextTags, certificate.tags)) {
      patch.tags = nextTags
    }
    const currentNotBefore = toLocalInput(certificate.notBefore)
    if (notBefore !== currentNotBefore) {
      patch.notBefore = notBefore
        ? new Date(notBefore).toISOString()
        : undefined
    }
    if (purgeProtection !== null) {
      patch.purgeProtection = purgeProtection
    }

    if (Object.keys(patch).length === 0) {
      setError("Nothing to save — no attribute has changed.")
      return
    }

    setError(null)
    save.mutate(patch)
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle>Attributes</CardTitle>
        <CardDescription>
          What this certificate is called, how it is labelled, and whether it
          answers reads right now.
        </CardDescription>
      </CardHeader>
      <CardContent className="flex flex-col gap-5">
        <Field orientation="horizontal">
          <FieldContent>
            <FieldLabel htmlFor="cert-enabled">Enabled</FieldLabel>
            <FieldDescription>
              A disabled certificate is refused on read with a 403 — it stays in
              the list, but cannot be opened until it is re-enabled.
            </FieldDescription>
          </FieldContent>
          <Switch
            id="cert-enabled"
            checked={certificate.enabled}
            disabled={save.isPending}
            onCheckedChange={(enabled) => save.mutate({ enabled })}
          />
        </Field>

        <Separator />

        <form onSubmit={handleSubmit}>
          <FieldGroup>
            <Field>
              <FieldLabel htmlFor="cert-name">Name</FieldLabel>
              <FieldContent>
                <Input
                  id="cert-name"
                  value={name}
                  onChange={(event) => setName(event.target.value)}
                />
              </FieldContent>
            </Field>

            <Field>
              <FieldLabel htmlFor="cert-tags">Tags</FieldLabel>
              <FieldContent>
                <Input
                  id="cert-tags"
                  value={tags}
                  placeholder="env=prod, owner=platform"
                  onChange={(event) => setTags(event.target.value)}
                />
                <FieldDescription>
                  Comma-separated labels. Saving replaces the whole set.
                </FieldDescription>
              </FieldContent>
            </Field>

            <Field>
              <FieldLabel htmlFor="cert-not-before">Valid from</FieldLabel>
              <FieldContent>
                <Input
                  id="cert-not-before"
                  type="datetime-local"
                  value={notBefore}
                  onChange={(event) => setNotBefore(event.target.value)}
                />
                <FieldDescription>
                  Before this moment the certificate is refused on read, the
                  same way a disabled one is.
                </FieldDescription>
              </FieldContent>
            </Field>

            <Field orientation="horizontal">
              <FieldContent>
                <FieldLabel htmlFor="cert-purge-protection">
                  Purge protection
                </FieldLabel>
                <FieldDescription>
                  Write-only: no certificate response reports the stored value,
                  so this shows what you are about to set, not what is set now.
                  It is saved only if you move it.
                </FieldDescription>
              </FieldContent>
              <Switch
                id="cert-purge-protection"
                checked={purgeProtection ?? false}
                disabled={save.isPending}
                onCheckedChange={setPurgeProtection}
              />
            </Field>

            <Field>
              <FieldLabel>Issuance</FieldLabel>
              <FieldContent>
                <Tooltip>
                  <TooltipTrigger
                    render={
                      <p className="w-fit text-sm text-muted-foreground underline decoration-dotted underline-offset-4" />
                    }
                  >
                    The signing key and CA issuer are fixed at issuance.
                  </TooltipTrigger>
                  <TooltipContent className="max-w-[40ch]">
                    A certificate's key is chosen when it is issued and its CA
                    issuer is set at creation and never changes, so the update
                    request carries neither. Neither is reported back by any
                    certificate response either, so there is nothing to show
                    here beyond this note. Re-issue the certificate to change
                    them.
                  </TooltipContent>
                </Tooltip>
              </FieldContent>
            </Field>

            {error && <FieldError>{error}</FieldError>}
          </FieldGroup>

          <div className="mt-6 flex justify-end">
            <Button type="submit" disabled={save.isPending}>
              {save.isPending ? "Saving…" : "Save changes"}
            </Button>
          </div>
        </form>
      </CardContent>
    </Card>
  )
}
