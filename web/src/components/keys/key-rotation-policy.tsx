import { useEffect, useState } from "react"
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"

import {
  clearRotationPolicy,
  getRotationPolicy,
  type RotationPolicyInput,
  setRotationPolicy,
} from "@/api/keys"
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
import { validateRotationPolicy } from "@/components/keys/rotation-policy-validation"
import { Switch } from "@/components/ui/switch"
import { formatRelativeTime } from "@/lib/format"

const EMPTY_FORM: RotationPolicyInput = {
  rotateAfterDays: 90,
  notifyBeforeExpiryDays: 30,
  expiryDays: 365,
  enabled: true,
}

/**
 * The automated schedule, deliberately a separate card from the manual
 * "Rotate now" button in <KeyVersions>: one describes what the server will do
 * on its own, the other is something the operator does right now.
 */
export function KeyRotationPolicyCard({
  vaultName,
  keyId,
}: {
  vaultName: string
  keyId: string
}) {
  const queryClient = useQueryClient()
  const [form, setForm] = useState<RotationPolicyInput>(EMPTY_FORM)
  const [error, setError] = useState<string | null>(null)
  const [saved, setSaved] = useState(false)
  const [removeOpen, setRemoveOpen] = useState(false)

  const { data, isLoading } = useQuery({
    queryKey: ["keys", vaultName, "rotation-policy", keyId],
    queryFn: () => getRotationPolicy(vaultName, keyId),
    // The backend answers 404 both for "no such key" and for "no policy set",
    // and the second is the normal state of a brand-new key -- so a 404 is
    // rendered as "no schedule", never as an error, and is not retried.
    retry: false,
  })

  useEffect(() => {
    if (data) {
      setForm({
        rotateAfterDays: data.rotateAfterDays,
        notifyBeforeExpiryDays: data.notifyBeforeExpiryDays,
        expiryDays: data.expiryDays,
        enabled: data.enabled,
      })
    }
  }, [data])

  const save = useMutation({
    mutationFn: () => setRotationPolicy(vaultName, keyId, form),
    onSuccess: async () => {
      setSaved(true)
      setError(null)
      await queryClient.invalidateQueries({
        queryKey: ["keys", vaultName, "rotation-policy", keyId],
      })
    },
    onError: (mutationError) => {
      setSaved(false)
      setError(
        mutationError instanceof ApiError
          ? mutationError.message
          : "Failed to save the rotation schedule."
      )
    },
  })

  const remove = useMutation({
    mutationFn: () => clearRotationPolicy(vaultName, keyId),
    onSuccess: async () => {
      setRemoveOpen(false)
      setSaved(false)
      setForm(EMPTY_FORM)
      await queryClient.invalidateQueries({
        queryKey: ["keys", vaultName, "rotation-policy", keyId],
      })
    },
    onError: (mutationError) => {
      setRemoveOpen(false)
      setError(
        mutationError instanceof ApiError
          ? mutationError.message
          : "Failed to remove the rotation schedule."
      )
    },
  })

  function handleSubmit(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault()
    setSaved(false)
    const validationError = validateRotationPolicy(form)
    if (validationError) {
      setError(validationError)
      return
    }
    setError(null)
    save.mutate()
  }

  function updateNumber(field: keyof RotationPolicyInput, raw: string) {
    setForm((previous) => ({ ...previous, [field]: Number(raw) }))
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle>Automatic rotation</CardTitle>
        <CardDescription>
          A schedule the server acts on by itself. Separate from the manual
          "Rotate now" action above.
        </CardDescription>
      </CardHeader>
      <CardContent className="flex flex-col gap-4">
        {isLoading ? (
          <Skeleton className="h-40 w-full rounded-3xl" />
        ) : (
          <>
            {!data && (
              <p className="text-sm text-muted-foreground">
                No automatic rotation schedule is set for this key. Fill the
                fields below to create one.
              </p>
            )}
            {data?.nextRotationAt && data.enabled && (
              <p className="text-sm">
                Next rotation {formatRelativeTime(data.nextRotationAt)}.
              </p>
            )}

            <form onSubmit={handleSubmit}>
              <FieldGroup>
                <Field orientation="horizontal">
                  <FieldContent>
                    <FieldLabel htmlFor="rotation-enabled">
                      Schedule enabled
                    </FieldLabel>
                    <FieldDescription>
                      A disabled schedule is stored but never acted on.
                    </FieldDescription>
                  </FieldContent>
                  <Switch
                    id="rotation-enabled"
                    checked={form.enabled}
                    onCheckedChange={(enabled) =>
                      setForm((previous) => ({ ...previous, enabled }))
                    }
                  />
                </Field>

                <Field>
                  <FieldLabel htmlFor="rotation-after">
                    Rotate every (days)
                  </FieldLabel>
                  <FieldContent>
                    <Input
                      id="rotation-after"
                      type="number"
                      min={0}
                      value={form.rotateAfterDays}
                      onChange={(event) =>
                        updateNumber("rotateAfterDays", event.target.value)
                      }
                    />
                    <FieldDescription>
                      The server enforces a minimum of one week while the
                      schedule is enabled.
                    </FieldDescription>
                  </FieldContent>
                </Field>

                <Field>
                  <FieldLabel htmlFor="rotation-notify">
                    Notify before expiry (days)
                  </FieldLabel>
                  <FieldContent>
                    <Input
                      id="rotation-notify"
                      type="number"
                      min={0}
                      value={form.notifyBeforeExpiryDays}
                      onChange={(event) =>
                        updateNumber(
                          "notifyBeforeExpiryDays",
                          event.target.value
                        )
                      }
                    />
                  </FieldContent>
                </Field>

                <Field>
                  <FieldLabel htmlFor="rotation-expiry">
                    Expire after (days)
                  </FieldLabel>
                  <FieldContent>
                    <Input
                      id="rotation-expiry"
                      type="number"
                      min={0}
                      value={form.expiryDays}
                      onChange={(event) =>
                        updateNumber("expiryDays", event.target.value)
                      }
                    />
                  </FieldContent>
                </Field>

                {error && <FieldError>{error}</FieldError>}
                {saved && !error && (
                  <p className="text-sm text-success">Schedule saved.</p>
                )}

                <div className="flex flex-wrap gap-3">
                  <Button type="submit" disabled={save.isPending}>
                    {save.isPending ? "Saving…" : "Save schedule"}
                  </Button>
                  {data && (
                    <AlertDialog open={removeOpen} onOpenChange={setRemoveOpen}>
                      <AlertDialogTrigger render={<Button variant="outline" />}>
                        Remove schedule
                      </AlertDialogTrigger>
                      <AlertDialogContent>
                        <AlertDialogHeader>
                          <AlertDialogTitle>
                            Remove the rotation schedule?
                          </AlertDialogTitle>
                          <AlertDialogDescription>
                            The key and all of its versions are untouched — only
                            the schedule goes away, so the key stops rotating on
                            its own until you set a new one.
                          </AlertDialogDescription>
                        </AlertDialogHeader>
                        <AlertDialogFooter>
                          <AlertDialogCancel>Cancel</AlertDialogCancel>
                          <AlertDialogAction
                            render={<Button variant="destructive" />}
                            onClick={() => remove.mutate()}
                          >
                            Remove
                          </AlertDialogAction>
                        </AlertDialogFooter>
                      </AlertDialogContent>
                    </AlertDialog>
                  )}
                </div>
              </FieldGroup>
            </form>
          </>
        )}
      </CardContent>
    </Card>
  )
}
