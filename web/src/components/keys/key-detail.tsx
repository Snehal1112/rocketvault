import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import { CpuIcon, ShieldAlertIcon } from "lucide-react"

import { getKey, type Key, updateKey } from "@/api/keys"
import { ApiError } from "@/api/types"
import { CopyValue } from "@/components/patterns/copy-value"
import { KeyBackupCard } from "@/components/keys/key-backup-card"
import { KeyCryptoPlayground } from "@/components/keys/key-crypto-playground"
import { KeyDangerZone } from "@/components/keys/key-danger-zone"
import { KeyRotationPolicyCard } from "@/components/keys/key-rotation-policy"
import { KeyStatus } from "@/components/keys/key-status"
import { KeyVersions } from "@/components/keys/key-versions"
import { describeKeyMaterial, isHsmBacked } from "@/components/keys/key-type"
import { Badge } from "@/components/ui/badge"
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card"
import {
  Empty,
  EmptyDescription,
  EmptyHeader,
  EmptyMedia,
  EmptyTitle,
} from "@/components/ui/empty"
import {
  Field,
  FieldContent,
  FieldDescription,
  FieldLabel,
} from "@/components/ui/field"
import { Skeleton } from "@/components/ui/skeleton"
import { Switch } from "@/components/ui/switch"
import { formatRelativeTime } from "@/lib/format"

/** Absolute timestamps are rendered in UTC on purpose: an operator comparing
 * a key's expiry against a server-side audit log needs the same clock the
 * server used, not their own. */
function formatUtc(iso: string | undefined): string | null {
  if (!iso) {
    return null
  }
  const parsed = new Date(iso)
  if (Number.isNaN(parsed.getTime())) {
    return null
  }
  return `${parsed.toISOString().slice(0, 16).replace("T", " ")} UTC`
}

function DetailRow({
  label,
  children,
}: {
  label: string
  children: React.ReactNode
}) {
  return (
    <div className="flex flex-col gap-0.5 sm:flex-row sm:items-baseline sm:gap-4">
      <dt className="w-40 shrink-0 text-sm text-muted-foreground">{label}</dt>
      <dd className="min-w-0 text-sm">{children}</dd>
    </div>
  )
}

function OverviewCard({ keyRecord }: { keyRecord: Key }) {
  const expires = formatUtc(keyRecord.expiresAt)
  const notBefore = formatUtc(keyRecord.notBefore)

  return (
    <Card>
      <CardHeader>
        <CardTitle>Overview</CardTitle>
        <CardDescription>
          What this key is and how long it stays usable.
        </CardDescription>
      </CardHeader>
      <CardContent>
        <dl className="flex flex-col gap-3">
          <DetailRow label="Identifier">
            <CopyValue value={keyRecord.id} label="key id" />
          </DetailRow>
          <DetailRow label="Type">
            <span className="font-heading">
              {describeKeyMaterial(keyRecord)}
            </span>
            {isHsmBacked(keyRecord.type) && (
              <span className="ml-2 inline-flex items-center gap-1.5 text-xs text-muted-foreground">
                <CpuIcon className="size-3.5" />
                Stored in HSM
              </span>
            )}
          </DetailRow>
          <DetailRow label="Created">
            {formatUtc(keyRecord.createdAt)} (
            {formatRelativeTime(keyRecord.createdAt)})
          </DetailRow>
          {keyRecord.updatedAt && (
            <DetailRow label="Last updated">
              {formatUtc(keyRecord.updatedAt)}
            </DetailRow>
          )}
          <DetailRow label="Expires">{expires ?? "Never"}</DetailRow>
          <DetailRow label="Valid from">{notBefore ?? "Immediately"}</DetailRow>
          <DetailRow label="Tags">
            {keyRecord.tags.length === 0 ? (
              <span className="text-muted-foreground">None</span>
            ) : (
              <span className="flex flex-wrap gap-1.5">
                {keyRecord.tags.map((tag) => (
                  <Badge key={tag} variant="secondary" className="font-heading">
                    {tag}
                  </Badge>
                ))}
              </span>
            )}
          </DetailRow>
        </dl>
      </CardContent>
    </Card>
  )
}

/**
 * Only the four public JWK components are ever rendered, each named
 * explicitly. The whole JWK object is deliberately NOT spread onto the page:
 * if a future backend change started emitting private material, this card
 * would keep ignoring it.
 */
function PublicKeyCard({ keyRecord }: { keyRecord: Key }) {
  const { n, e, x, y } = keyRecord.publicJwk
  const hasComponents = Boolean(n || e || x || y)

  return (
    <Card>
      <CardHeader>
        <CardTitle>Public key</CardTitle>
        <CardDescription>
          The public JWK components, base64url-encoded. Private material is
          never returned by the API and is never shown here.
        </CardDescription>
      </CardHeader>
      <CardContent className="flex flex-col gap-4">
        {!hasComponents && (
          <p className="text-sm text-muted-foreground">
            {isHsmBacked(keyRecord.type)
              ? "This key is generated and used inside the HSM. Its material never leaves the HSM, so no JWK components are available."
              : "No public components were returned for this key."}
          </p>
        )}
        {n && <JwkComponent name="n" description="Modulus" value={n} />}
        {e && <JwkComponent name="e" description="Exponent" value={e} />}
        {x && <JwkComponent name="x" description="X coordinate" value={x} />}
        {y && <JwkComponent name="y" description="Y coordinate" value={y} />}
      </CardContent>
    </Card>
  )
}

function JwkComponent({
  name,
  description,
  value,
}: {
  name: string
  description: string
  value: string
}) {
  return (
    <div className="flex flex-col gap-1.5">
      <p className="text-sm">
        <span className="font-heading">{name}</span>
        <span className="ml-2 text-muted-foreground">{description}</span>
      </p>
      <CopyValue value={value} label={`JWK ${name}`} />
    </div>
  )
}

/**
 * Availability toggles save on change rather than behind a Save button:
 * each is a single, independently-granted backend field, and an operator
 * disabling a leaked key wants it off now, not after a second click.
 */
function AvailabilityCard({
  vaultName,
  keyRecord,
}: {
  vaultName: string
  keyRecord: Key
}) {
  const queryClient = useQueryClient()

  const mutation = useMutation({
    mutationFn: (patch: { enabled?: boolean; revoked?: boolean }) =>
      updateKey(vaultName, keyRecord.id, patch),
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: ["keys", vaultName] })
    },
  })

  return (
    <Card>
      <CardHeader>
        <CardTitle>Availability</CardTitle>
        <CardDescription>
          Whether this key answers cryptographic requests right now.
        </CardDescription>
      </CardHeader>
      <CardContent className="flex flex-col gap-5">
        <Field orientation="horizontal">
          <FieldContent>
            <FieldLabel htmlFor="key-enabled">Enabled</FieldLabel>
            <FieldDescription>
              A disabled key rejects every sign, verify, encrypt and wrap
              request until it is re-enabled.
            </FieldDescription>
          </FieldContent>
          <Switch
            id="key-enabled"
            checked={keyRecord.enabled}
            disabled={mutation.isPending}
            onCheckedChange={(enabled) => mutation.mutate({ enabled })}
          />
        </Field>
        <Field orientation="horizontal">
          <FieldContent>
            <FieldLabel htmlFor="key-revoked">Revoked</FieldLabel>
            <FieldDescription>
              Marks the key as no longer trusted. The material is kept so
              existing signatures stay verifiable, but new operations are
              refused.
            </FieldDescription>
          </FieldContent>
          <Switch
            id="key-revoked"
            checked={keyRecord.revoked}
            disabled={mutation.isPending}
            onCheckedChange={(revoked) => mutation.mutate({ revoked })}
          />
        </Field>
        {mutation.error && (
          <p role="alert" className="text-sm text-destructive">
            {mutation.error instanceof ApiError
              ? mutation.error.message
              : "Failed to update the key."}
          </p>
        )}
      </CardContent>
    </Card>
  )
}

export function KeyDetail({
  vaultName,
  keyId,
}: {
  vaultName: string
  keyId: string
}) {
  const { data, isLoading, error } = useQuery({
    queryKey: ["keys", vaultName, "detail", keyId],
    queryFn: () => getKey(vaultName, keyId),
  })

  if (isLoading) {
    return (
      <div className="mx-auto flex w-full max-w-4xl flex-col gap-6 p-6">
        <Skeleton className="h-10 w-64 rounded-4xl" />
        <Skeleton className="h-64 w-full rounded-4xl" />
        <Skeleton className="h-48 w-full rounded-4xl" />
      </div>
    )
  }

  if (error || !data) {
    return (
      <Empty>
        <EmptyHeader>
          <EmptyMedia variant="icon">
            <ShieldAlertIcon />
          </EmptyMedia>
          <EmptyTitle>Key unavailable</EmptyTitle>
          <EmptyDescription>
            {error instanceof ApiError
              ? error.message
              : "Could not load this key."}
          </EmptyDescription>
        </EmptyHeader>
      </Empty>
    )
  }

  return (
    <div className="mx-auto flex w-full max-w-4xl flex-col gap-6 p-6">
      <header className="flex flex-wrap items-start justify-between gap-4">
        <div>
          <h1 className="font-heading text-2xl font-medium tracking-tight">
            {data.name}
          </h1>
          <p className="mt-1 flex flex-wrap items-center gap-2 text-sm text-muted-foreground">
            <span className="font-heading text-foreground">
              {describeKeyMaterial(data)}
            </span>
            <span aria-hidden="true">·</span>
            <span>Created {formatRelativeTime(data.createdAt)}</span>
          </p>
        </div>
        <KeyStatus keyRecord={data} />
      </header>

      <OverviewCard keyRecord={data} />
      <PublicKeyCard keyRecord={data} />
      <AvailabilityCard vaultName={vaultName} keyRecord={data} />
      <KeyCryptoPlayground vaultName={vaultName} keyRecord={data} />
      <KeyVersions vaultName={vaultName} keyId={data.id} />
      <KeyRotationPolicyCard vaultName={vaultName} keyId={data.id} />
      <KeyBackupCard
        vaultName={vaultName}
        keyId={data.id}
        keyName={data.name}
      />
      <KeyDangerZone
        vaultName={vaultName}
        keyId={data.id}
        keyName={data.name}
      />
    </div>
  )
}
