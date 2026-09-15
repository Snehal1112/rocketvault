import type { ReactNode } from "react"
import { useQuery } from "@tanstack/react-query"
import { ShieldAlertIcon } from "lucide-react"

import { type Certificate, getCertificate } from "@/api/certificates"
import { ApiError } from "@/api/types"
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
    return (
      <Empty>
        <EmptyHeader>
          <EmptyMedia variant="icon">
            <ShieldAlertIcon />
          </EmptyMedia>
          <EmptyTitle>Certificate unavailable</EmptyTitle>
          <EmptyDescription>
            {error instanceof ApiError
              ? error.message
              : "Could not load this certificate."}
          </EmptyDescription>
        </EmptyHeader>
      </Empty>
    )
  }

  return (
    <>
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

      <OverviewCard certificate={data} />
    </>
  )
}
