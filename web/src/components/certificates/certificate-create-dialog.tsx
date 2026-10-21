import { useState } from "react"
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import { useNavigate } from "@tanstack/react-router"
import { PlusIcon } from "lucide-react"

import {
  type Certificate,
  createCertificate,
  listCertificates,
} from "@/api/certificates"
import { listKeys } from "@/api/keys"
import { ApiError } from "@/api/types"
import { Button } from "@/components/ui/button"
import {
  Combobox,
  ComboboxContent,
  ComboboxEmpty,
  ComboboxInput,
  ComboboxItem,
  ComboboxList,
} from "@/components/ui/combobox"
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
import { Switch } from "@/components/ui/switch"

interface PickerOption {
  id: string
  name: string
}

/** Comma-separated labels, matching how the keys dialog parses them -- the
 * backend takes a plain string array, so a blank field sends nothing rather
 * than an empty array. */
function parseTags(raw: string): string[] | undefined {
  const tags = raw
    .split(",")
    .map((tag) => tag.trim())
    .filter(Boolean)
  return tags.length > 0 ? tags : undefined
}

/**
 * A searchable picker over an existing resource in the same vault. Used for
 * both the signing key (required) and the CA certificate (optional): a vault
 * can hold many of either, and a UUID is not something an operator can type
 * from memory.
 */
function ResourcePicker({
  id,
  options,
  value,
  onValueChange,
  placeholder,
  emptyLabel,
}: {
  id: string
  options: PickerOption[]
  value: string | null
  onValueChange: (next: string | null) => void
  placeholder: string
  emptyLabel: string
}) {
  return (
    <Combobox
      items={options}
      itemToStringLabel={(item: PickerOption) => item.name}
      value={options.find((option) => option.id === value) ?? null}
      onValueChange={(item: PickerOption | null) =>
        onValueChange(item ? item.id : null)
      }
    >
      <ComboboxInput id={id} placeholder={placeholder} showClear />
      <ComboboxContent>
        <ComboboxEmpty>{emptyLabel}</ComboboxEmpty>
        <ComboboxList>
          {(option: PickerOption) => (
            <ComboboxItem key={option.id} value={option}>
              <span className="font-heading">{option.name}</span>
            </ComboboxItem>
          )}
        </ComboboxList>
      </ComboboxContent>
    </Combobox>
  )
}

/**
 * Issues a certificate over a key the vault already holds.
 *
 * Two things this dialog deliberately does NOT offer:
 *   * a `ca_key_id` field -- the backend struct has one but it is explicitly
 *     unused, so surfacing it would imply a control that does nothing;
 *   * generating a key inline -- issuance requires an existing key id, and
 *     silently creating one would leave a stray key behind on a failed issue.
 */
export function CertificateCreateDialog({ vaultName }: { vaultName: string }) {
  const navigate = useNavigate()
  const queryClient = useQueryClient()

  const [open, setOpen] = useState(false)
  const [name, setName] = useState("")
  const [keyId, setKeyId] = useState<string | null>(null)
  const [caCertId, setCaCertId] = useState<string | null>(null)
  const [validityDays, setValidityDays] = useState(365)
  const [tags, setTags] = useState("")
  const [autoRenew, setAutoRenew] = useState(false)
  const [renewalDays, setRenewalDays] = useState(30)
  const [isCa, setIsCa] = useState(false)
  const [enabled, setEnabled] = useState(true)
  const [notBefore, setNotBefore] = useState("")
  const [purgeProtection, setPurgeProtection] = useState(false)
  const [error, setError] = useState<string | null>(null)

  // Both pickers only matter while the dialog is open, and a caller without
  // keys_read still has to be able to see the certificate list behind it --
  // so neither query is allowed to retry or to surface its own failure here.
  const { data: keys } = useQuery({
    queryKey: ["keys", vaultName, "list"],
    queryFn: () => listKeys(vaultName),
    enabled: open,
    retry: false,
  })

  const { data: certificates } = useQuery({
    queryKey: ["certificates", vaultName, "list"],
    queryFn: () => listCertificates(vaultName),
    enabled: open,
    retry: false,
  })

  const issue = useMutation({
    mutationFn: (): Promise<Certificate> =>
      createCertificate(vaultName, {
        name,
        // Non-null by construction: handleSubmit refuses to fire without one.
        keyId: keyId ?? "",
        validityDays,
        tags: parseTags(tags),
        autoRenew,
        renewalDays,
        // Omitted entirely when unset, so the backend takes the self-signed
        // path rather than trying to resolve an empty UUID.
        ...(caCertId ? { caCertId } : {}),
        isCa,
        enabled,
        ...(notBefore ? { notBefore: new Date(notBefore).toISOString() } : {}),
        purgeProtection,
      }),
    onSuccess: async (certificate) => {
      await queryClient.invalidateQueries({
        queryKey: ["certificates", vaultName],
      })
      setOpen(false)
      navigate({
        to: "/vaults/$vaultName/certificates/$certificateId",
        params: { vaultName, certificateId: certificate.id },
      })
    },
    onError: (mutationError) =>
      setError(
        mutationError instanceof ApiError
          ? mutationError.message
          : "Failed to issue the certificate."
      ),
  })

  function handleSubmit(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault()
    setError(null)

    // Guarded client-side rather than posting an empty key_id: the backend
    // would answer a generic 400 on "key_id", which reads as a bug rather
    // than as "you forgot to pick a key".
    if (!keyId) {
      setError("Pick the key this certificate is issued over.")
      return
    }
    if (validityDays <= 0) {
      setError("Validity must be at least one day.")
      return
    }

    issue.mutate()
  }

  const keyOptions: PickerOption[] = (keys ?? []).map((key) => ({
    id: key.id,
    name: key.name,
  }))
  // A certificate cannot sign itself, and only a CA certificate is a
  // meaningful issuer -- but `is_ca` is not on the list response, so every
  // certificate is offered and the server rejects a non-CA choice.
  const caOptions: PickerOption[] = (certificates ?? []).map((certificate) => ({
    id: certificate.id,
    name: certificate.name,
  }))

  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger render={<Button />}>
        <PlusIcon />
        Issue certificate
      </DialogTrigger>
      <DialogContent className="max-h-[85vh] overflow-y-auto">
        <DialogHeader>
          <DialogTitle>Issue a certificate</DialogTitle>
          <DialogDescription>
            Issued over a key this vault already holds. Leave the CA field empty
            for a self-signed certificate.
          </DialogDescription>
        </DialogHeader>

        <form onSubmit={handleSubmit}>
          <FieldGroup>
            <Field>
              <FieldLabel htmlFor="cert-create-name">Common name</FieldLabel>
              <FieldContent>
                <Input
                  id="cert-create-name"
                  value={name}
                  onChange={(event) => setName(event.target.value)}
                  placeholder="api.example.com"
                  required
                />
              </FieldContent>
            </Field>

            <Field>
              <FieldLabel htmlFor="cert-create-key">Signing key</FieldLabel>
              <FieldContent>
                <ResourcePicker
                  id="cert-create-key"
                  options={keyOptions}
                  value={keyId}
                  onValueChange={setKeyId}
                  placeholder="Search keys in this vault"
                  emptyLabel="No matching key in this vault"
                />
                <FieldDescription>
                  Required, and fixed for the life of the certificate. Create
                  the key first if the one you want is not listed.
                </FieldDescription>
              </FieldContent>
            </Field>

            <Field>
              <FieldLabel htmlFor="cert-create-ca">
                Sign with a CA certificate (optional)
              </FieldLabel>
              <FieldContent>
                <ResourcePicker
                  id="cert-create-ca"
                  options={caOptions}
                  value={caCertId}
                  onValueChange={setCaCertId}
                  placeholder="Self-signed"
                  emptyLabel="No other certificate in this vault"
                />
                <FieldDescription>
                  Leave empty to self-sign. The issuer must itself be a CA
                  certificate.
                </FieldDescription>
              </FieldContent>
            </Field>

            <Field>
              <FieldLabel htmlFor="cert-create-validity">
                Validity (days)
              </FieldLabel>
              <FieldContent>
                <Input
                  id="cert-create-validity"
                  type="number"
                  min={1}
                  value={validityDays}
                  onChange={(event) =>
                    setValidityDays(Number(event.target.value))
                  }
                />
              </FieldContent>
            </Field>

            <Field>
              <FieldLabel htmlFor="cert-create-not-before">
                Valid from (optional)
              </FieldLabel>
              <FieldContent>
                <Input
                  id="cert-create-not-before"
                  type="datetime-local"
                  value={notBefore}
                  onChange={(event) => setNotBefore(event.target.value)}
                />
                <FieldDescription>
                  Leave empty to activate immediately.
                </FieldDescription>
              </FieldContent>
            </Field>

            <Field>
              <FieldLabel htmlFor="cert-create-tags">
                Tags (optional)
              </FieldLabel>
              <FieldContent>
                <Input
                  id="cert-create-tags"
                  placeholder="env=prod, owner=platform"
                  value={tags}
                  onChange={(event) => setTags(event.target.value)}
                />
                <FieldDescription>Comma-separated labels.</FieldDescription>
              </FieldContent>
            </Field>

            <Field orientation="horizontal">
              <FieldContent>
                <FieldLabel htmlFor="cert-create-auto-renew">
                  Auto-renew
                </FieldLabel>
                <FieldDescription>
                  The renewal scheduler reads this setting, not the certificate
                  policy's.
                </FieldDescription>
              </FieldContent>
              <Switch
                id="cert-create-auto-renew"
                checked={autoRenew}
                onCheckedChange={setAutoRenew}
              />
            </Field>

            {autoRenew && (
              <Field>
                <FieldLabel htmlFor="cert-create-renewal-days">
                  Renew this many days before expiry
                </FieldLabel>
                <FieldContent>
                  <Input
                    id="cert-create-renewal-days"
                    type="number"
                    min={1}
                    value={renewalDays}
                    onChange={(event) =>
                      setRenewalDays(Number(event.target.value))
                    }
                  />
                </FieldContent>
              </Field>
            )}

            <Field orientation="horizontal">
              <FieldContent>
                <FieldLabel htmlFor="cert-create-is-ca">
                  Certificate authority
                </FieldLabel>
                <FieldDescription>
                  Issues this as a CA, so other certificates in the vault can be
                  signed with it.
                </FieldDescription>
              </FieldContent>
              <Switch
                id="cert-create-is-ca"
                checked={isCa}
                onCheckedChange={setIsCa}
              />
            </Field>

            <Field orientation="horizontal">
              <FieldContent>
                <FieldLabel htmlFor="cert-create-enabled">Enabled</FieldLabel>
                <FieldDescription>
                  A disabled certificate cannot be read back until it is
                  re-enabled.
                </FieldDescription>
              </FieldContent>
              <Switch
                id="cert-create-enabled"
                checked={enabled}
                onCheckedChange={setEnabled}
              />
            </Field>

            <Field orientation="horizontal">
              <FieldContent>
                <FieldLabel htmlFor="cert-create-purge-protection">
                  Purge protection
                </FieldLabel>
                <FieldDescription>
                  Blocks a permanent purge after deletion, until the protection
                  is lifted.
                </FieldDescription>
              </FieldContent>
              <Switch
                id="cert-create-purge-protection"
                checked={purgeProtection}
                onCheckedChange={setPurgeProtection}
              />
            </Field>

            {error && <FieldError>{error}</FieldError>}
          </FieldGroup>

          <DialogFooter className="mt-6">
            <Button type="submit" disabled={issue.isPending}>
              {issue.isPending ? "Issuing…" : "Issue certificate"}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}
