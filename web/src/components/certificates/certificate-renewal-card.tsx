import { useEffect, useState } from "react"
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
  FieldLabel,
} from "@/components/ui/field"
import { Input } from "@/components/ui/input"
import { Switch } from "@/components/ui/switch"

/**
 * The certificate's OWN renewal settings -- and the only ones that do
 * anything.
 *
 * The renewal scheduler reads this certificate's `auto_renew`,
 * `renewal_days` and `expires_at` columns, and never consults the certificate
 * policy's `auto_renew`/`days_before_expiry`
 * (internal/services/certificates/certificate_service.go:128-134). That split
 * is invisible from the API alone, so the copy here and in
 * <CertificatePolicyForm> exists to keep it from becoming a silent
 * mis-configuration.
 *
 * There is deliberately NO "Renew now" button. No HTTP route registers
 * renewal: `rocketvault certificates renew <id>` calls the service directly,
 * and api/certificates.go's route list has no renew entry. Shipping a button
 * would mean inventing an endpoint. The CLI command is named instead.
 */
export function CertificateRenewalCard({
  vaultName,
  certificate,
}: {
  vaultName: string
  certificate: Certificate
}) {
  const queryClient = useQueryClient()
  const [renewalDays, setRenewalDays] = useState(certificate.renewalDays)
  const [error, setError] = useState<string | null>(null)

  // Re-seeded whenever the server's value changes, so a save elsewhere (a
  // second tab, another operator) is not silently overwritten by a stale
  // draft -- mirrors <CertificatePolicyForm>'s same guard.
  useEffect(() => {
    setRenewalDays(certificate.renewalDays)
  }, [certificate.renewalDays])

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
          : "Failed to update the renewal settings."
      ),
  })

  function handleSaveWindow() {
    if (renewalDays < 1) {
      setError("The renewal window must be at least one day.")
      return
    }
    if (renewalDays === certificate.renewalDays) {
      setError("Nothing to save — the renewal window has not changed.")
      return
    }
    setError(null)
    save.mutate({ renewalDays })
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle>Renewal</CardTitle>
        <CardDescription>
          These are the settings the renewal scheduler acts on. The certificate
          policy below describes how a replacement would be issued; it does not
          decide whether one is.
        </CardDescription>
      </CardHeader>
      <CardContent className="flex flex-col gap-5">
        <Field orientation="horizontal">
          <FieldContent>
            <FieldLabel htmlFor="cert-auto-renew">
              Renew automatically
            </FieldLabel>
            <FieldDescription>
              The scheduler reissues this certificate once it comes inside the
              window below. It only runs at all when the server is started with
              certificate rotation enabled, which the API does not report — so
              treat this as a request, and confirm the first renewal actually
              happened.
            </FieldDescription>
          </FieldContent>
          <Switch
            id="cert-auto-renew"
            checked={certificate.autoRenew}
            disabled={save.isPending}
            onCheckedChange={(autoRenew) => save.mutate({ autoRenew })}
          />
        </Field>

        <Field>
          <FieldLabel htmlFor="cert-renewal-days">
            Days before expiry
          </FieldLabel>
          <FieldContent>
            <div className="flex flex-wrap items-center gap-3">
              <Input
                id="cert-renewal-days"
                type="number"
                min={1}
                className="w-32"
                value={renewalDays}
                onChange={(event) => setRenewalDays(Number(event.target.value))}
              />
              <Button
                type="button"
                variant="outline"
                disabled={save.isPending}
                onClick={handleSaveWindow}
              >
                {save.isPending ? "Saving…" : "Save"}
              </Button>
            </div>
            <FieldDescription>
              How far ahead of <span className="font-heading">expires_at</span>{" "}
              the scheduler starts trying. The list screen warns you inside this
              same window.
            </FieldDescription>
          </FieldContent>
        </Field>

        {error && <FieldError>{error}</FieldError>}

        <p className="text-sm text-muted-foreground">
          Renewing on demand is a CLI-only operation today — the server
          registers no HTTP route for it. Run{" "}
          <code className="font-heading text-foreground">
            rocketvault certificates renew {certificate.id}
          </code>{" "}
          to force one now.
        </p>
      </CardContent>
    </Card>
  )
}
