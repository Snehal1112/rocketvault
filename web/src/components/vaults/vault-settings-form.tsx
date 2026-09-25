import { useEffect, useState } from "react"
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"

import { ApiError } from "@/api/types"
import { getVault, type UpdateVaultInput, updateVault } from "@/api/vaults"
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
import { Skeleton } from "@/components/ui/skeleton"
import { Switch } from "@/components/ui/switch"

export function VaultSettingsForm({ vaultName }: { vaultName: string }) {
  const queryClient = useQueryClient()
  const { data: vault } = useQuery({
    queryKey: ["vaults", "detail", vaultName],
    queryFn: () => getVault(vaultName),
  })

  const [enabled, setEnabled] = useState<boolean | null>(null)
  const [purgeProtection, setPurgeProtection] = useState<boolean | null>(null)
  const [retentionDays, setRetentionDays] = useState("")
  const [error, setError] = useState<string | null>(null)
  const [saved, setSaved] = useState(false)

  useEffect(() => {
    if (!vault) {
      return
    }
    setEnabled(vault.enabled)
    setPurgeProtection(vault.purgeProtection)
    setRetentionDays(String(vault.retentionDays))
  }, [vault])

  const mutation = useMutation({
    mutationFn: (patch: UpdateVaultInput) => updateVault(vaultName, patch),
    onSuccess: async () => {
      setError(null)
      setSaved(true)
      await queryClient.invalidateQueries({
        queryKey: ["vaults", "detail", vaultName],
      })
    },
    onError: (mutationError) => {
      setSaved(false)
      setError(
        mutationError instanceof ApiError
          ? mutationError.message
          : "Failed to update vault."
      )
    },
  })

  function handleSubmit(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (!vault) {
      return
    }
    setError(null)
    setSaved(false)

    // Only explicitly-changed fields are sent -- mirrors the CLI's and
    // src/api/vaults.ts's updateVault() partial-update contract.
    const patch: UpdateVaultInput = {}
    if (enabled !== null && enabled !== vault.enabled) {
      patch.enabled = enabled
    }
    if (purgeProtection !== null && purgeProtection !== vault.purgeProtection) {
      patch.purgeProtection = purgeProtection
    }
    const retentionDaysNumber = Number(retentionDays)
    if (
      retentionDays !== "" &&
      !Number.isNaN(retentionDaysNumber) &&
      retentionDaysNumber !== vault.retentionDays
    ) {
      patch.retentionDays = retentionDaysNumber
    }

    mutation.mutate(patch)
  }

  if (!vault || enabled === null) {
    return (
      <Card>
        <CardContent className="flex flex-col gap-4">
          <Skeleton className="h-10 w-full" />
          <Skeleton className="h-10 w-full" />
          <Skeleton className="h-10 w-2/3" />
        </CardContent>
      </Card>
    )
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle>General</CardTitle>
        <CardDescription>
          Availability and how long deleted items stay recoverable.
        </CardDescription>
      </CardHeader>
      <CardContent>
        <form onSubmit={handleSubmit}>
          <FieldGroup>
            <Field orientation="horizontal">
              <FieldContent>
                <FieldLabel htmlFor="vault-settings-enabled">
                  Enabled
                </FieldLabel>
                <FieldDescription>
                  Disabled vaults reject all data-plane requests.
                </FieldDescription>
              </FieldContent>
              <Switch
                id="vault-settings-enabled"
                checked={enabled}
                onCheckedChange={setEnabled}
              />
            </Field>
            <Field orientation="horizontal">
              <FieldContent>
                <FieldLabel htmlFor="vault-settings-purge-protection">
                  Purge protection
                </FieldLabel>
                <FieldDescription>
                  Prevents this vault from ever being permanently purged.
                </FieldDescription>
              </FieldContent>
              <Switch
                id="vault-settings-purge-protection"
                checked={purgeProtection ?? false}
                onCheckedChange={setPurgeProtection}
              />
            </Field>
            <Field>
              <FieldLabel htmlFor="vault-settings-retention">
                Retention (days)
              </FieldLabel>
              <FieldContent>
                <Input
                  id="vault-settings-retention"
                  type="number"
                  min={0}
                  value={retentionDays}
                  onChange={(event) => setRetentionDays(event.target.value)}
                />
                <FieldDescription>
                  How long a deleted secret, key, or certificate stays
                  recoverable before it is purged automatically.
                </FieldDescription>
              </FieldContent>
            </Field>
            {error && <FieldError>{error}</FieldError>}
            {saved && !error && (
              <p className="text-sm text-success">Vault updated.</p>
            )}
            <Button type="submit" disabled={mutation.isPending}>
              {mutation.isPending ? "Saving…" : "Save changes"}
            </Button>
          </FieldGroup>
        </form>
      </CardContent>
    </Card>
  )
}
