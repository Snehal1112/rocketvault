package repositories

import (
	"context"
	"fmt"

	"github.com/google/uuid"

	"rocketvault/internal/db"
)

// principalGrantTables lists the tables that grant a principal something. None
// has a foreign key on principal_id, because a principal is either a users row
// or an oauth2_clients row, so each delete path must clear them itself.
var principalGrantTables = []string{"role_assignments", "access_policies", "vault_provisioning_grants"}

// deletePrincipalGrants removes every grant held by principalID on ex. Callers
// pass the transaction that deletes the principal, so both happen or neither.
func deletePrincipalGrants(ctx context.Context, ex db.DBTX, principalID uuid.UUID) error {
	for _, table := range principalGrantTables {
		// The table name comes from the fixed list above, never from input.
		query := "DELETE FROM " + table + " WHERE principal_id = ?"
		if _, err := ex.ExecContext(ctx, query, principalID.String()); err != nil {
			return fmt.Errorf("failed to delete %s for principal: %w", table, err)
		}
	}
	return nil
}
