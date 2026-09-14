import { createRoute } from "@tanstack/react-router"
import { VaultIcon } from "lucide-react"

import {
  Empty,
  EmptyDescription,
  EmptyHeader,
  EmptyMedia,
  EmptyTitle,
} from "@/components/ui/empty"
import { vaultsRoute } from "@/routes/vaults"

// Placeholder -- replaced by the real vault picker/landing page (VaultList +
// VaultCreateDialog) in Epic 01's plan, Task 3.
function VaultsIndexPage() {
  return (
    <div className="flex min-h-svh items-center justify-center p-6">
      <Empty>
        <EmptyHeader>
          <EmptyMedia variant="icon">
            <VaultIcon />
          </EmptyMedia>
          <EmptyTitle>Vault picker coming in Epic 01</EmptyTitle>
          <EmptyDescription>
            Vault list, create, and settings screens land in Epic 01.
          </EmptyDescription>
        </EmptyHeader>
      </Empty>
    </div>
  )
}

export const vaultsIndexRoute = createRoute({
  getParentRoute: () => vaultsRoute,
  path: "/",
  component: VaultsIndexPage,
})
