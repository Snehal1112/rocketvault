import { useQuery } from "@tanstack/react-query"
import { Link } from "@tanstack/react-router"
import { ScrollTextIcon } from "lucide-react"

import { type Certificate, listCertificates } from "@/api/certificates"
import { CertificateAccessDenied } from "@/components/certificates/certificate-access-denied"
import { CertificateCreateDialog } from "@/components/certificates/certificate-create-dialog"
import { CertificateStatusDot } from "@/components/certificates/certificate-status-dot"
import {
  type CertificatesSummary,
  summarizeCertificates,
} from "@/components/certificates/certificate-status"
import { CardGrid } from "@/components/patterns/card-grid"
import { RESOURCE_CARD_LINK_CLASS } from "@/components/patterns/card-link-class"
import { ResourceListSkeleton } from "@/components/patterns/list-skeleton"
import { ResourceCardShell } from "@/components/patterns/resource-card"
import { StatGrid, StatTile } from "@/components/patterns/stat-tile"
import { Badge } from "@/components/ui/badge"
import {
  Empty,
  EmptyContent,
  EmptyDescription,
  EmptyHeader,
  EmptyMedia,
  EmptyTitle,
} from "@/components/ui/empty"
import { formatRelativeTime } from "@/lib/format"

function CertificateStatRow({ summary }: { summary: CertificatesSummary }) {
  return (
    <StatGrid aria-label="Certificate counts">
      <StatTile value={summary.total} label="Total" />
      <StatTile value={summary.expiringSoon} label="Expiring soon" />
      <StatTile value={summary.expired} label="Expired" />
    </StatGrid>
  )
}

/**
 * One certificate as a card the operator opens, per the design doc's
 * cards-for-navigation / tables-for-scanning rule -- a certificate has a
 * detail page (attributes, policy, renewal, danger zone), so it is navigated
 * into, exactly like a secret or a key.
 *
 * Only named fields are rendered. The response object is never spread onto
 * the page, so a backend that one day started emitting the PEM or the private
 * key (both exist on model.Certificate) still could not put them on screen.
 */
function CertificateCard({
  certificate,
  vaultName,
}: {
  certificate: Certificate
  vaultName: string
}) {
  return (
    <Link
      to="/vaults/$vaultName/certificates/$certificateId"
      params={{ vaultName, certificateId: certificate.id }}
      className={RESOURCE_CARD_LINK_CLASS}
    >
      <ResourceCardShell
        title={certificate.name}
        status={<CertificateStatusDot certificate={certificate} />}
      >
        <span>
          {certificate.expiresAt
            ? `Expires ${new Date(certificate.expiresAt)
                .toISOString()
                .slice(0, 10)}`
            : "No expiry set"}
        </span>
        <span>
          Issued {formatRelativeTime(certificate.createdAt)} ·{" "}
          {certificate.autoRenew
            ? `auto-renews ${certificate.renewalDays}d before expiry`
            : "no auto-renewal"}
        </span>
        {certificate.tags.length > 0 && (
          <div className="mt-2 flex flex-wrap gap-1.5">
            {certificate.tags.slice(0, 3).map((tag) => (
              <Badge key={tag} variant="secondary" className="font-heading">
                {tag}
              </Badge>
            ))}
            {certificate.tags.length > 3 && (
              <Badge variant="secondary">+{certificate.tags.length - 3}</Badge>
            )}
          </div>
        )}
      </ResourceCardShell>
    </Link>
  )
}

export function CertificateList({ vaultName }: { vaultName: string }) {
  const { data, isLoading, error } = useQuery({
    queryKey: ["certificates", vaultName, "list"],
    queryFn: () => listCertificates(vaultName),
  })

  if (isLoading) {
    return (
      <ResourceListSkeleton
        statCount={3}
        cardCount={6}
        cardHeightClassName="h-36"
      />
    )
  }

  // A denied read and an empty vault look identical if the error is swallowed,
  // and they call for opposite responses from the operator -- so the server's
  // own message is shown rather than an empty state.
  if (error) {
    return (
      <CertificateAccessDenied
        error={error}
        intent="read"
        title="Certificates unavailable"
        fallback="Could not load certificates for this vault."
      />
    )
  }

  if (!data || data.length === 0) {
    return (
      <Empty>
        <EmptyHeader>
          <EmptyMedia variant="icon">
            <ScrollTextIcon />
          </EmptyMedia>
          <EmptyTitle>Issue your first certificate</EmptyTitle>
          <EmptyDescription>
            A certificate is issued over a key this vault already holds, either
            self-signed or signed by a CA certificate you keep here.
          </EmptyDescription>
        </EmptyHeader>
        <EmptyContent>
          <CertificateCreateDialog vaultName={vaultName} />
        </EmptyContent>
      </Empty>
    )
  }

  return (
    <div className="flex flex-col gap-6">
      <CertificateStatRow summary={summarizeCertificates(data)} />
      <CardGrid>
        {data.map((certificate) => (
          <CertificateCard
            key={certificate.id}
            certificate={certificate}
            vaultName={vaultName}
          />
        ))}
      </CardGrid>
    </div>
  )
}
