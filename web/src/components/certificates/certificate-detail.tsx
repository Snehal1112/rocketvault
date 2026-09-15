import type { ReactNode } from "react"
import { useQuery } from "@tanstack/react-query"
import { Link } from "@tanstack/react-router"
import { ArrowLeftIcon, ClockAlertIcon, ShieldAlertIcon } from "lucide-react"

import { type Certificate, getCertificate } from "@/api/certificates"
import { ApiError } from "@/api/types"
import { CertificateAttributesForm } from "@/components/certificates/certificate-attributes-form"
import { isLifecycleDenial } from "@/components/certificates/certificate-errors"
import { CertificatePolicyForm } from "@/components/certificates/certificate-policy-form"
import { CertificateRenewalCard } from "@/components/certificates/certificate-renewal-card"
import { CertificateStatusDot } from "@/components/certificates/certificate-status-dot"
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
import { Skeleton } from "@/components/ui/skeleton"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { formatRelativeTime } from "@/lib/format"

/** Absolute timestamps are rendered in UTC on purpose: an operator comparing
 * a certificate's expiry against a server-side audit log needs the same clock
 * the server used, not their own. */
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
  children: ReactNode
}) {
  return (
    <div className="flex flex-col gap-0.5 sm:flex-row sm:items-baseline sm:gap-4">
      <dt className="w-40 shrink-0 text-sm text-muted-foreground">{label}</dt>
      <dd className="min-w-0 text-sm">{children}</dd>
    </div>
  )
}

/**
 * Every field is named explicitly rather than spread off the response.
 *
 * model.Certificate carries `Certificate` (the PEM) and `PrivateKey`
 * alongside this metadata; CertificateResponse projects neither today, and
 * this allow-list is what guarantees that a backend change which started
 * emitting them could not put them on screen by accident.
 */
function OverviewCard({ certificate }: { certificate: Certificate }) {
  return (
    <Card>
      <CardHeader>
        <CardTitle>Overview</CardTitle>
        <CardDescription>
          What this certificate covers and how long it stays valid.
        </CardDescription>
      </CardHeader>
      <CardContent>
        <dl className="flex flex-col gap-3">
          <DetailRow label="Identifier">
            <span className="font-heading break-all">{certificate.id}</span>
          </DetailRow>
          <DetailRow label="Common name">
            <span className="font-heading">{certificate.name}</span>
          </DetailRow>
          <DetailRow label="Issued">
            {formatUtc(certificate.createdAt)} (
            {formatRelativeTime(certificate.createdAt)})
          </DetailRow>
          <DetailRow label="Expires">
            {formatUtc(certificate.expiresAt) ?? "No expiry recorded"}
          </DetailRow>
          <DetailRow label="Valid from">
            {formatUtc(certificate.notBefore) ?? "Immediately"}
          </DetailRow>
          <DetailRow label="Tags">
            {certificate.tags.length === 0 ? (
              <span className="text-muted-foreground">None</span>
            ) : (
              <span className="flex flex-wrap gap-1.5">
                {certificate.tags.map((tag) => (
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

export function CertificateDetail({
  vaultName,
  certificateId,
}: {
  vaultName: string
  certificateId: string
}) {
  const { data, isLoading, error } = useQuery({
    queryKey: ["certificates", vaultName, "detail", certificateId],
    queryFn: () => getCertificate(vaultName, certificateId),
  })

  if (isLoading) {
    return (
      <div className="flex flex-col gap-6">
        <Skeleton className="h-10 w-64 rounded-4xl" />
        <Skeleton className="h-64 w-full rounded-4xl" />
      </div>
    )
  }

  if (error || !data) {
    return <CertificateUnavailable vaultName={vaultName} error={error} />
  }

  return (
    <>
      <BackToCertificates vaultName={vaultName} />
      <header className="flex flex-wrap items-start justify-between gap-4">
        <div>
          <h1 className="font-heading text-2xl font-medium tracking-tight">
            {data.name}
          </h1>
          <p className="mt-1 text-sm text-muted-foreground">
            Issued {formatRelativeTime(data.createdAt)}
          </p>
        </div>
        <CertificateStatusDot certificate={data} />
      </header>

      <Tabs defaultValue="overview">
        <TabsList>
          <TabsTrigger value="overview">Overview</TabsTrigger>
          <TabsTrigger value="renewal">Renewal &amp; policy</TabsTrigger>
        </TabsList>
        <TabsContent value="overview" className="flex flex-col gap-6 pt-6">
          <OverviewCard certificate={data} />
          <CertificateAttributesForm vaultName={vaultName} certificate={data} />
        </TabsContent>
        {/* The two renewal surfaces sit side by side on purpose: the split
            between them is the single most confusable thing about
            certificates, and separating them across tabs would hide it. */}
        <TabsContent value="renewal" className="flex flex-col gap-6 pt-6">
          <CertificateRenewalCard vaultName={vaultName} certificate={data} />
          <CertificatePolicyForm vaultName={vaultName} certificate={data} />
        </TabsContent>
      </Tabs>
    </>
  )
}

/** Always rendered on the detail screen, error state included -- a 403 here
 * is routine (a disabled certificate 403s on read), so the operator must
 * never be stranded on a dead end. */
function BackToCertificates({ vaultName }: { vaultName: string }) {
  return (
    <Link
      to="/vaults/$vaultName/certificates"
      params={{ vaultName }}
      className="inline-flex w-fit items-center gap-1.5 text-sm text-muted-foreground underline-offset-4 hover:text-foreground hover:underline"
    >
      <ArrowLeftIcon className="size-4" />
      All certificates
    </Link>
  )
}

/**
 * Distinguishes the certificate's own lifecycle state from a role denial.
 * Both arrive as a 403 with the same status code, and conflating them tells a
 * Certificates Officer they lack permission when the certificate is simply
 * disabled or expired.
 */
function CertificateUnavailable({
  vaultName,
  error,
}: {
  vaultName: string
  error: unknown
}) {
  const lifecycle = isLifecycleDenial(error)

  return (
    <>
      <BackToCertificates vaultName={vaultName} />
      <Empty>
        <EmptyHeader>
          <EmptyMedia variant="icon">
            {lifecycle ? <ClockAlertIcon /> : <ShieldAlertIcon />}
          </EmptyMedia>
          <EmptyTitle>
            {lifecycle
              ? "This certificate is not readable right now"
              : "Certificate unavailable"}
          </EmptyTitle>
          <EmptyDescription>
            {lifecycle
              ? "The server reports that this certificate is disabled or outside its valid time window. That is a state of the certificate, not of your access — re-enable it, or wait until its valid-from date, and it will open."
              : error instanceof ApiError
                ? error.message
                : "Could not load this certificate."}
          </EmptyDescription>
        </EmptyHeader>
      </Empty>
    </>
  )
}
