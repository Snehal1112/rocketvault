import { createRoute } from "@tanstack/react-router"
import { ShieldIcon } from "lucide-react"

import {
  Empty,
  EmptyDescription,
  EmptyHeader,
  EmptyMedia,
  EmptyTitle,
} from "@/components/ui/empty"
import { adminRoute } from "@/routes/admin"

// Placeholder -- platform administration (users, service accounts, access
// policies, provisioning grants, audit, JWKS) is Epics 07-12, out of scope
// for this plan.
function AdminIndexPage() {
  return (
    <Empty>
      <EmptyHeader>
        <EmptyMedia variant="icon">
          <ShieldIcon />
        </EmptyMedia>
        <EmptyTitle>Admin console coming in Epics 07-12</EmptyTitle>
        <EmptyDescription>
          User management, service accounts, access policies, provisioning
          grants, audit, and JWKS screens land in later epics.
        </EmptyDescription>
      </EmptyHeader>
    </Empty>
  )
}

export const adminIndexRoute = createRoute({
  getParentRoute: () => adminRoute,
  path: "/",
  component: AdminIndexPage,
})
