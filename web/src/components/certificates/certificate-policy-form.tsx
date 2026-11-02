import { useEffect, useState } from "react"
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import { FileTextIcon, TriangleAlertIcon } from "lucide-react"

import {
  type Certificate,
  type CertificatePolicy,
  type CertificatePolicyInput,
  deleteCertificatePolicy,
  getCertificatePolicy,
  upsertCertificatePolicy,
} from "@/api/certificates"
import { ApiError } from "@/api/types"
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
  AlertDialogTrigger,
} from "@/components/ui/alert-dialog"
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import { Button } from "@/components/ui/button"
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card"
import {
  Empty,
  EmptyContent,
  EmptyDescription,
  EmptyHeader,
  EmptyMedia,
  EmptyTitle,
} from "@/components/ui/empty"
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
import { Skeleton } from "@/components/ui/skeleton"
import { Switch } from "@/components/ui/switch"

const KEY_TYPES = ["RSA", "ECDSA"]
const RSA_SIZES = [2048, 3072, 4096]
const CURVES = ["P-256", "P-384", "P-521"]

interface PolicyDraft {
  validityMonths: string
  keyType: string
  keySize: string
  curve: string
  subject: string
  sans: string
  autoRenew: boolean
  daysBeforeExpiry: string
  issuerName: string
}

function draftFrom(policy: CertificatePolicy | null): PolicyDraft {
  return {
    validityMonths: policy ? String(policy.validityMonths) : "12",
    keyType: policy?.keyType || "RSA",
    keySize: policy?.keySize ? String(policy.keySize) : "2048",
    curve: policy?.curve || "P-256",
    subject: policy?.subject ?? "",
    sans: policy?.sans ?? "",
    autoRenew: policy?.autoRenew ?? false,
    daysBeforeExpiry: policy ? String(policy.daysBeforeExpiry) : "30",
    issuerName: policy?.issuerName ?? "",
  }
}

/**
 * The certificate policy: a template describing how a REPLACEMENT would be
 * issued (key type, subject, SANs, validity), not a schedule.
 *
 * Its `auto_renew` and `days_before_expiry` fields look exactly like the
 * certificate's own, and are not read by anything -- the renewal scheduler
 * consults the certificate's columns only
 * (internal/services/certificates/certificate_service.go:128-134). The inline
 * notice below fires on precisely the combination that would otherwise look
 * like working auto-renewal and silently be nothing at all.
 */
export function CertificatePolicyForm({
  vaultName,
  certificate,
}: {
  vaultName: string
  certificate: Certificate
}) {
  const queryClient = useQueryClient()
  const [editing, setEditing] = useState(false)
  const [draft, setDraft] = useState<PolicyDraft>(draftFrom(null))
  const [error, setError] = useState<string | null>(null)

  const {
    data: policy,
    isLoading,
    error: loadError,
  } = useQuery({
    // A 404 resolves to null rather than throwing: "no policy set" and "no
    // such certificate" share a status code here, and the former is the
    // common case.
    queryKey: ["certificates", vaultName, "policy", certificate.id],
    queryFn: () => getCertificatePolicy(vaultName, certificate.id),
    retry: false,
  })

  // Re-seeded whenever the server's policy changes, so a save elsewhere is
  // not silently overwritten by a stale draft.
  useEffect(() => {
    if (policy !== undefined) {
      setDraft(draftFrom(policy ?? null))
    }
  }, [policy])

  const save = useMutation({
    mutationFn: (input: CertificatePolicyInput) =>
      upsertCertificatePolicy(vaultName, certificate.id, input),
    onSuccess: async () => {
      setError(null)
      setEditing(false)
      await queryClient.invalidateQueries({
        queryKey: ["certificates", vaultName, "policy", certificate.id],
      })
    },
    onError: (mutationError) =>
      setError(
        mutationError instanceof ApiError
          ? mutationError.message
          : "Failed to save the policy."
      ),
  })

  const clear = useMutation({
    mutationFn: () => deleteCertificatePolicy(vaultName, certificate.id),
    onSuccess: async () => {
      setError(null)
      setEditing(false)
      await queryClient.invalidateQueries({
        queryKey: ["certificates", vaultName, "policy", certificate.id],
      })
    },
    onError: (mutationError) =>
      setError(
        mutationError instanceof ApiError
          ? mutationError.message
          : "Failed to delete the policy."
      ),
  })

  function handleSubmit(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault()

    // Mirrors the CLI's own guard: a policy upsert replaces the stored policy
    // wholesale, so these two cannot be inferred from what is already there.
    if (!draft.subject.trim()) {
      setError("Subject is required — for example CN=api.example.com.")
      return
    }
    const validityMonths = Number(draft.validityMonths)
    if (!Number.isFinite(validityMonths) || validityMonths < 1) {
      setError("Validity months is required and must be at least 1.")
      return
    }

    setError(null)
    save.mutate({
      validityMonths,
      keyType: draft.keyType,
      ...(draft.keyType === "RSA" ? { keySize: Number(draft.keySize) } : {}),
      ...(draft.keyType === "ECDSA" ? { curve: draft.curve } : {}),
      subject: draft.subject.trim(),
      sans: draft.sans.trim(),
      autoRenew: draft.autoRenew,
      daysBeforeExpiry: Number(draft.daysBeforeExpiry) || 0,
      issuerName: draft.issuerName.trim(),
    })
  }

  if (isLoading) {
    return <Skeleton className="h-64 w-full rounded-4xl" />
  }

  // A real failure (403, 500) is distinct from "no policy" -- the API module
  // already folded 404 into null before it reached here.
  if (loadError) {
    return (
      <Card>
        <CardHeader>
          <CardTitle>Certificate policy</CardTitle>
          <CardDescription>
            {loadError instanceof ApiError
              ? loadError.message
              : "Could not read this certificate's policy."}
          </CardDescription>
        </CardHeader>
      </Card>
    )
  }

  const showEditor = editing || policy !== null

  return (
    <Card>
      <CardHeader>
        <CardTitle>Certificate policy</CardTitle>
        <CardDescription>
          The template a reissued certificate is built from — its subject, SANs,
          key type and validity. Saving replaces the stored policy outright.
        </CardDescription>
      </CardHeader>
      <CardContent className="flex flex-col gap-5">
        {!showEditor ? (
          <Empty>
            <EmptyHeader>
              <EmptyMedia variant="icon">
                <FileTextIcon />
              </EmptyMedia>
              <EmptyTitle>No policy set</EmptyTitle>
              <EmptyDescription>
                Without one, a renewal reuses this certificate's existing
                subject and validity. Set a policy to control how a replacement
                is issued.
              </EmptyDescription>
            </EmptyHeader>
            <EmptyContent>
              <Button onClick={() => setEditing(true)}>Set a policy</Button>
            </EmptyContent>
          </Empty>
        ) : (
          <form onSubmit={handleSubmit}>
            <FieldGroup>
              <Field>
                <FieldLabel htmlFor="policy-subject">Subject</FieldLabel>
                <FieldContent>
                  <Input
                    id="policy-subject"
                    value={draft.subject}
                    placeholder="CN=api.example.com"
                    onChange={(event) =>
                      setDraft({ ...draft, subject: event.target.value })
                    }
                  />
                  <FieldDescription>
                    Required. The distinguished name a reissued certificate
                    carries.
                  </FieldDescription>
                </FieldContent>
              </Field>

              <Field>
                <FieldLabel htmlFor="policy-sans">
                  Subject alternative names
                </FieldLabel>
                <FieldContent>
                  <Input
                    id="policy-sans"
                    value={draft.sans}
                    placeholder="DNS:api.example.com,DNS:www.example.com"
                    onChange={(event) =>
                      setDraft({ ...draft, sans: event.target.value })
                    }
                  />
                  <FieldDescription>
                    A single comma-separated string, not a list — that is the
                    shape the API stores.
                  </FieldDescription>
                </FieldContent>
              </Field>

              <Field>
                <FieldLabel htmlFor="policy-validity">
                  Validity (months)
                </FieldLabel>
                <FieldContent>
                  <Input
                    id="policy-validity"
                    type="number"
                    min={1}
                    value={draft.validityMonths}
                    onChange={(event) =>
                      setDraft({ ...draft, validityMonths: event.target.value })
                    }
                  />
                  <FieldDescription>Required.</FieldDescription>
                </FieldContent>
              </Field>

              <Field>
                <FieldLabel htmlFor="policy-key-type">Key type</FieldLabel>
                <FieldContent>
                  <NativeSelect
                    id="policy-key-type"
                    className="w-full"
                    value={draft.keyType}
                    onChange={(event) =>
                      setDraft({ ...draft, keyType: event.target.value })
                    }
                  >
                    {KEY_TYPES.map((type) => (
                      <NativeSelectOption key={type} value={type}>
                        {type}
                      </NativeSelectOption>
                    ))}
                  </NativeSelect>
                </FieldContent>
              </Field>

              {draft.keyType === "RSA" && (
                <Field>
                  <FieldLabel htmlFor="policy-key-size">Key size</FieldLabel>
                  <FieldContent>
                    <NativeSelect
                      id="policy-key-size"
                      className="w-full"
                      value={draft.keySize}
                      onChange={(event) =>
                        setDraft({ ...draft, keySize: event.target.value })
                      }
                    >
                      {RSA_SIZES.map((size) => (
                        <NativeSelectOption key={size} value={String(size)}>
                          {size} bits
                        </NativeSelectOption>
                      ))}
                    </NativeSelect>
                  </FieldContent>
                </Field>
              )}

              {draft.keyType === "ECDSA" && (
                <Field>
                  <FieldLabel htmlFor="policy-curve">Curve</FieldLabel>
                  <FieldContent>
                    <NativeSelect
                      id="policy-curve"
                      className="w-full"
                      value={draft.curve}
                      onChange={(event) =>
                        setDraft({ ...draft, curve: event.target.value })
                      }
                    >
                      {CURVES.map((curve) => (
                        <NativeSelectOption key={curve} value={curve}>
                          {curve}
                        </NativeSelectOption>
                      ))}
                    </NativeSelect>
                  </FieldContent>
                </Field>
              )}

              <Field>
                <FieldLabel htmlFor="policy-issuer">Issuer name</FieldLabel>
                <FieldContent>
                  <Input
                    id="policy-issuer"
                    value={draft.issuerName}
                    onChange={(event) =>
                      setDraft({ ...draft, issuerName: event.target.value })
                    }
                  />
                </FieldContent>
              </Field>

              <PolicyRenewalNotice
                policyAutoRenew={draft.autoRenew}
                certificateAutoRenew={certificate.autoRenew}
              />

              <Field orientation="horizontal">
                <FieldContent>
                  <FieldLabel htmlFor="policy-auto-renew">
                    Auto-renew (template only)
                  </FieldLabel>
                  <FieldDescription>
                    Recorded on the policy and read by nothing. Renewal is
                    driven by the certificate's own setting in the Renewal card.
                  </FieldDescription>
                </FieldContent>
                <Switch
                  id="policy-auto-renew"
                  checked={draft.autoRenew}
                  onCheckedChange={(autoRenew) =>
                    setDraft({ ...draft, autoRenew })
                  }
                />
              </Field>

              <Field>
                <FieldLabel htmlFor="policy-days-before-expiry">
                  Days before expiry (template only)
                </FieldLabel>
                <FieldContent>
                  <Input
                    id="policy-days-before-expiry"
                    type="number"
                    min={0}
                    className="w-32"
                    value={draft.daysBeforeExpiry}
                    onChange={(event) =>
                      setDraft({
                        ...draft,
                        daysBeforeExpiry: event.target.value,
                      })
                    }
                  />
                </FieldContent>
              </Field>

              {error && <FieldError>{error}</FieldError>}
            </FieldGroup>

            <div className="mt-6 flex flex-wrap items-center justify-end gap-3">
              {policy !== null && (
                <AlertDialog>
                  <AlertDialogTrigger
                    render={<Button type="button" variant="outline" />}
                  >
                    Delete policy
                  </AlertDialogTrigger>
                  <AlertDialogContent>
                    <AlertDialogHeader>
                      <AlertDialogTitle>
                        Delete this certificate's policy?
                      </AlertDialogTitle>
                      <AlertDialogDescription>
                        The certificate itself is untouched. A future renewal
                        falls back to reusing the certificate's existing subject
                        and validity instead of this template.
                      </AlertDialogDescription>
                    </AlertDialogHeader>
                    <AlertDialogFooter>
                      <AlertDialogCancel>Cancel</AlertDialogCancel>
                      <AlertDialogAction
                        render={<Button variant="destructive" />}
                        onClick={() => clear.mutate()}
                      >
                        Delete
                      </AlertDialogAction>
                    </AlertDialogFooter>
                  </AlertDialogContent>
                </AlertDialog>
              )}
              <Button type="submit" disabled={save.isPending}>
                {save.isPending ? "Saving…" : "Save policy"}
              </Button>
            </div>
          </form>
        )}
      </CardContent>
    </Card>
  )
}

/**
 * Fires on exactly one combination: the policy asks for auto-renewal while
 * the certificate itself does not. That pairing reads as working
 * auto-renewal, produces no renewals at all, and is only discoverable by
 * watching a certificate expire.
 */
function PolicyRenewalNotice({
  policyAutoRenew,
  certificateAutoRenew,
}: {
  policyAutoRenew: boolean
  certificateAutoRenew: boolean
}) {
  if (!policyAutoRenew || certificateAutoRenew) {
    return null
  }

  return (
    <Alert variant="destructive">
      <TriangleAlertIcon />
      <AlertTitle>This policy will not renew anything</AlertTitle>
      <AlertDescription>
        The policy's auto-renew and days-before-expiry describe the re-issuance
        template and are not read by the renewal scheduler. The scheduler reads
        the certificate's own auto-renew setting, which is currently off — turn
        it on in the Renewal card above.
      </AlertDescription>
    </Alert>
  )
}
