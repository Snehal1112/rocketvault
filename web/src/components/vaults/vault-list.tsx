import { useQuery } from "@tanstack/react-query"
import { Link } from "@tanstack/react-router"
import { VaultIcon } from "lucide-react"

import { listVaults } from "@/api/vaults"
import { VaultCreateDialog } from "@/components/vaults/vault-create-dialog"
import { Badge } from "@/components/ui/badge"
import {
  Empty,
  EmptyContent,
  EmptyDescription,
  EmptyHeader,
  EmptyMedia,
  EmptyTitle,
} from "@/components/ui/empty"
import { Skeleton } from "@/components/ui/skeleton"
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table"

export function VaultList() {
  const { data, isLoading } = useQuery({
    queryKey: ["vaults", "list"],
    queryFn: () => listVaults(),
  })

  if (isLoading) {
    return (
      <div className="flex flex-col gap-2">
        <Skeleton className="h-10 w-full" />
        <Skeleton className="h-10 w-full" />
        <Skeleton className="h-10 w-full" />
      </div>
    )
  }

  if (!data || data.length === 0) {
    return (
      <Empty>
        <EmptyHeader>
          <EmptyMedia variant="icon">
            <VaultIcon />
          </EmptyMedia>
          <EmptyTitle>No vaults yet</EmptyTitle>
          <EmptyDescription>
            Create your first vault to start storing secrets, keys, and
            certificates.
          </EmptyDescription>
        </EmptyHeader>
        <EmptyContent>
          <VaultCreateDialog />
        </EmptyContent>
      </Empty>
    )
  }

  return (
    <div className="flex flex-col gap-4">
      <div className="flex justify-end">
        <VaultCreateDialog />
      </div>
      <Table>
        <TableHeader>
          <TableRow>
            <TableHead className="font-heading">Name</TableHead>
            <TableHead className="font-heading">Status</TableHead>
            <TableHead className="font-heading">Retention</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {data.map((vault) => (
            <TableRow key={vault.id}>
              <TableCell>
                <Link
                  to="/vaults/$vaultName/secrets"
                  params={{ vaultName: vault.name }}
                  className="font-medium hover:underline"
                >
                  {vault.name}
                </Link>
              </TableCell>
              <TableCell>
                <Badge variant={vault.enabled ? "default" : "secondary"}>
                  {vault.enabled ? "Enabled" : "Disabled"}
                </Badge>
              </TableCell>
              <TableCell>{vault.retentionDays} days</TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
    </div>
  )
}
