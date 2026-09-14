import { createRoute } from "@tanstack/react-router"
import { UserIcon } from "lucide-react"

import {
  Empty,
  EmptyDescription,
  EmptyHeader,
  EmptyMedia,
  EmptyTitle,
} from "@/components/ui/empty"
import { requireAuth } from "@/lib/auth/guards"
import { rootRoute } from "@/routes/__root"

// Placeholder -- own sessions list/revoke, profile, and logout are Epic 13,
// out of scope for this plan. Authenticated but unscoped, per the design
// doc §2 -- neither vault- nor admin-role guarded, just requireAuth.
function AccountPage() {
  return (
    <Empty>
      <EmptyHeader>
        <EmptyMedia variant="icon">
          <UserIcon />
        </EmptyMedia>
        <EmptyTitle>Account & sessions coming in Epic 13</EmptyTitle>
        <EmptyDescription>
          Your session list, profile, and sign-out-everywhere controls land in
          Epic 13.
        </EmptyDescription>
      </EmptyHeader>
    </Empty>
  )
}

export const accountRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/account",
  beforeLoad: () => {
    requireAuth()
  },
  component: AccountPage,
})
