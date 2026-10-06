import { createRoute, Outlet } from "@tanstack/react-router"

import { vaultLayoutRoute } from "@/routes/vaults.$vaultName"

/**
 * Layout for the certificates section. The section's own screens are
 * children: the index (list), "deleted" (soft-delete recovery), and
 * "$certificateId" (detail).
 *
 * Note the param is an ID, not a name, diverging from the secrets and keys
 * sections' naming: every certificate route matches
 * "{certificate_id:[A-Fa-f0-9-]+}" (../../../api/certificates.go:106) and the
 * backend registers no name lookup at all.
 */
export const vaultCertificatesRoute = createRoute({
  getParentRoute: () => vaultLayoutRoute,
  path: "certificates",
  component: () => <Outlet />,
})
