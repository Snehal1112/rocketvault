import { ShieldAlertIcon } from "lucide-react"

import { ApiError } from "@/api/types"
import { isLifecycleDenial } from "@/components/certificates/certificate-errors"
import {
  Empty,
  EmptyDescription,
  EmptyHeader,
  EmptyMedia,
  EmptyTitle,
} from "@/components/ui/empty"

// Verbatim from model/azure_roles.go -- an operator has to be able to paste
// these into a `vault-access grant` command or hand them to whoever runs it,
// so a paraphrase would be useless.
const READ_ROLES = ["Key Vault Certificate User", "Key Vault Reader"]
const WRITE_ROLES = [
  "Key Vault Certificates Officer",
  "Key Vault Administrator",
]

/**
 * The error state for any certificate read, with one extra thing to say when
 * the failure is a role denial: which per-vault role would fix it.
 *
 * There is deliberately no client-side permission pre-check anywhere in this
 * epic. A vault-scoped grant cannot be resolved before the first real data
 * call, and no endpoint reports the caller's own roles in a vault -- so a
 * guard would have to guess, and a wrong guess either hides a screen the
 * caller can use or promises one they cannot.
 *
 * A lifecycle 403 is explicitly excluded: that one is the certificate's own
 * state and is handled by <CertificateDetail>, which would otherwise tell a
 * Certificates Officer to go ask for the role they already hold.
 */
export function CertificateAccessDenied({
  error,
  title,
  fallback,
  /** "read" names the two read-capable roles; "write" names the two that can
   * issue or modify. */
  intent,
}: {
  error: unknown
  title: string
  fallback: string
  intent: "read" | "write"
}) {
  const roleDenied =
    error instanceof ApiError &&
    error.statusCode === 403 &&
    !isLifecycleDenial(error)

  const roles = intent === "write" ? WRITE_ROLES : READ_ROLES

  return (
    <Empty>
      <EmptyHeader>
        <EmptyMedia variant="icon">
          <ShieldAlertIcon />
        </EmptyMedia>
        <EmptyTitle>{title}</EmptyTitle>
        <EmptyDescription>
          {error instanceof ApiError ? error.message : fallback}
          {roleDenied && (
            <>
              {" "}
              This vault grants certificate access by role. Ask an administrator
              for{" "}
              <span className="font-heading text-foreground">
                {roles[0]}
              </span>{" "}
              or{" "}
              <span className="font-heading text-foreground">{roles[1]}</span>{" "}
              on{" "}
              {intent === "write"
                ? "this vault to issue or modify certificates."
                : "this vault to view its certificates."}
            </>
          )}
        </EmptyDescription>
      </EmptyHeader>
    </Empty>
  )
}
