import { createRoute } from "@tanstack/react-router"
import { KeyRoundIcon } from "lucide-react"

import {
  Empty,
  EmptyDescription,
  EmptyHeader,
  EmptyMedia,
  EmptyTitle,
} from "@/components/ui/empty"
import { vaultLayoutRoute } from "@/routes/vaults.$vaultName"

// Placeholder -- the default vault tab. Real secrets CRUD lands in Epic 02
// (out of scope for this plan); this exists so the route tree is fully
// navigable end to end, per this task's goal.
function VaultSecretsPage() {
  return (
    <Empty>
      <EmptyHeader>
        <EmptyMedia variant="icon">
          <KeyRoundIcon />
        </EmptyMedia>
        <EmptyTitle>Secrets coming in Epic 02</EmptyTitle>
        <EmptyDescription>
          Secret CRUD, versions, and soft-delete land in Epic 02.
        </EmptyDescription>
      </EmptyHeader>
    </Empty>
  )
}

export const vaultSecretsRoute = createRoute({
  getParentRoute: () => vaultLayoutRoute,
  path: "secrets",
  component: VaultSecretsPage,
})
