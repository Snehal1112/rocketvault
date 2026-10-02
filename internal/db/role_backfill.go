package db

import (
	"context"
	"database/sql"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"

	"rocketvault/model"
)

// RoleBackfillGrant is one (principal, role, vault) assignment the P2 upgrade
// migration would create. Source records which ownership table implied it, so
// an operator reviewing a preview can tell a derived grant from an admin grant.
type RoleBackfillGrant struct {
	PrincipalID string
	VaultID     string
	VaultName   string
	Role        string
	Source      string
}

// ownershipBackfillSource pairs an ownership table with the Azure role its
// owners receive in the vault holding the objects they own.
type ownershipBackfillSource struct {
	Table string
	Role  string
}

// ownershipBackfillSources is the mapping from spec section 6.3 steps 1 and 2.
var ownershipBackfillSources = []ownershipBackfillSource{
	{Table: "secrets", Role: model.RoleKeyVaultSecretsOfficer},
	{Table: "keys", Role: model.RoleKeyVaultCryptoOfficer},
	{Table: "certificates", Role: model.RoleKeyVaultCertificatesOfficer},
}

// legacyRoleToAzureRole maps every pre-Azure-RBAC vault-scoped role name (the
// builtInRoles keys in internal/services/authorization/roles.go) to the Azure
// built-in role it corresponds to. The role_assignments table and this
// vocabulary shipped in RocketVault v0.2.0 (2026-06-06), well before the
// Task 9 deny-by-default PolicyMiddleware inversion, which is evaluated
// entirely against model.RoleGrantsDataAction and understands only the thirteen
// Azure names. Without this translation, a principal holding only a legacy
// role like "secrets-officer" -- and who happens to own no objects directly,
// so the ownership-derived sources above never see them -- grants zero data
// actions and is silently locked out on upgrade.
var legacyRoleToAzureRole = map[string]string{
	"vault-admin":          model.RoleKeyVaultAdministrator,
	"vault-reader":         model.RoleKeyVaultReader,
	"secrets-user":         model.RoleKeyVaultSecretsUser,
	"secrets-officer":      model.RoleKeyVaultSecretsOfficer,
	"crypto-user":          model.RoleKeyVaultCryptoUser,
	"crypto-officer":       model.RoleKeyVaultCryptoOfficer,
	"certificates-officer": model.RoleKeyVaultCertificatesOfficer,
}

// legacyRoleAssignmentSource is the RoleBackfillGrant.Source value for grants
// derived by translating an existing legacy-named role_assignments row.
const legacyRoleAssignmentSource = "legacy-role-assignment"

// PlanRoleBackfill derives the role assignments the P2 upgrade migration would
// create from existing object ownership. It writes nothing, so the migration and
// the "rocketvault vaults preview-migration" command run the same computation
// and an operator's preview is exactly what the upgrade will do.
//
// Derivation, per spec section 6.3, plus a fourth source added once the
// role_assignments table itself was found to predate this migration (it
// shipped in v0.2.0, well before P2):
//  1. Each distinct secrets.user_id owning rows in a vault -> Key Vault Secrets Officer there.
//  2. Same for keys -> Key Vault Crypto Officer and certificates -> Key Vault Certificates Officer.
//  3. Every user holding the global admin role -> Key Vault Administrator in every vault.
//  4. Every existing role_assignments row already using a legacy vault-scoped role
//     name (see legacyRoleToAzureRole) -> the equivalent Azure built-in role, for the
//     same (principal, vault).
//
// A source table missing its ownership columns is skipped: migrateSchema runs
// against arbitrary old shapes, and secrets.user_id predates secrets.vault_id.
// The same applies to role_assignments missing principal_id/vault_id/role: it
// shouldn't happen (the table is created well before this function ever runs),
// but the check costs nothing and matches the fail-safe already established for
// the ownership sources.
// A vault_id with no vaults row is skipped too, because role_assignments has a
// foreign key to vaults(id).
//
// The result is sorted by (vault name, role, principal) so output is stable.
func PlanRoleBackfill(ctx context.Context, q DBTX, dialect Dialect) ([]RoleBackfillGrant, error) {
	vaultNames, err := vaultNamesByID(ctx, q)
	if err != nil {
		return nil, err
	}
	if len(vaultNames) == 0 {
		return nil, nil
	}

	type grantKey struct{ principal, vault, role string }
	seen := map[grantKey]bool{}
	var grants []RoleBackfillGrant

	add := func(principal, vault, role, source string) {
		name, known := vaultNames[vault]
		if principal == "" || vault == "" || !known {
			return
		}
		k := grantKey{principal, vault, role}
		if seen[k] {
			return
		}
		seen[k] = true
		grants = append(grants, RoleBackfillGrant{
			PrincipalID: principal,
			VaultID:     vault,
			VaultName:   name,
			Role:        role,
			Source:      source,
		})
	}

	for _, src := range ownershipBackfillSources {
		usable, err := hasOwnershipColumns(ctx, q, dialect, src.Table)
		if err != nil {
			return nil, err
		}
		if !usable {
			continue
		}
		if err := scanOwnership(ctx, q, src, add); err != nil {
			return nil, err
		}
	}

	adminIDs, err := globalAdminIDs(ctx, q, dialect)
	if err != nil {
		return nil, err
	}
	for _, adminID := range adminIDs {
		for vaultID := range vaultNames {
			add(adminID, vaultID, model.RoleKeyVaultAdministrator, "global-admin")
		}
	}

	usable, err := hasRoleAssignmentColumns(ctx, q, dialect)
	if err != nil {
		return nil, err
	}
	if usable {
		if err := scanLegacyRoleAssignments(ctx, q, add); err != nil {
			return nil, err
		}
	}

	sort.Slice(grants, func(i, j int) bool {
		if grants[i].VaultName != grants[j].VaultName {
			return grants[i].VaultName < grants[j].VaultName
		}
		if grants[i].Role != grants[j].Role {
			return grants[i].Role < grants[j].Role
		}
		return grants[i].PrincipalID < grants[j].PrincipalID
	})
	return grants, nil
}

// vaultNamesByID returns every vault id mapped to its name.
func vaultNamesByID(ctx context.Context, q DBTX) (map[string]string, error) {
	rows, err := q.QueryContext(ctx, `SELECT id, name FROM vaults`)
	if err != nil {
		return nil, fmt.Errorf("list vaults for role backfill: %w", err)
	}
	defer rows.Close() //nolint:errcheck
	out := map[string]string{}
	for rows.Next() {
		var id, name string
		if err := rows.Scan(&id, &name); err != nil {
			return nil, fmt.Errorf("scan vault for role backfill: %w", err)
		}
		out[id] = name
	}
	return out, rows.Err()
}

// hasOwnershipColumns reports whether the table carries both ownership columns
// the backfill reads. A table missing either is skipped, not an error.
func hasOwnershipColumns(ctx context.Context, q DBTX, dialect Dialect, table string) (bool, error) {
	hasUser, err := dialect.ColumnExists(ctx, q, table, "user_id")
	if err != nil {
		return false, fmt.Errorf("inspect %s.user_id: %w", table, err)
	}
	if !hasUser {
		return false, nil
	}
	hasVault, err := dialect.ColumnExists(ctx, q, table, "vault_id")
	if err != nil {
		return false, fmt.Errorf("inspect %s.vault_id: %w", table, err)
	}
	return hasVault, nil
}

// scanOwnership walks the distinct (owner, vault) pairs in one source table.
// The table name is a compile-time constant from ownershipBackfillSources, never
// caller input, so interpolating it introduces no injection surface.
func scanOwnership(ctx context.Context, q DBTX, src ownershipBackfillSource,
	add func(principal, vault, role, source string)) error {
	query := fmt.Sprintf(
		`SELECT DISTINCT user_id, vault_id FROM %s WHERE user_id IS NOT NULL AND user_id <> ''`, src.Table)
	rows, err := q.QueryContext(ctx, query)
	if err != nil {
		return fmt.Errorf("scan %s ownership: %w", src.Table, err)
	}
	defer rows.Close() //nolint:errcheck
	for rows.Next() {
		var userID, vaultID string
		if err := rows.Scan(&userID, &vaultID); err != nil {
			return fmt.Errorf("scan %s ownership row: %w", src.Table, err)
		}
		add(userID, vaultID, src.Role, src.Table)
	}
	return rows.Err()
}

// hasRoleAssignmentColumns reports whether role_assignments carries the three
// columns the legacy-role scan reads. Matches the hasOwnershipColumns
// fail-safe pattern: the table is created well before PlanRoleBackfill ever
// runs against a real deployment, but PlanRoleBackfill is also called directly
// in tests and previews against minimal, purpose-built schemas, so the check
// keeps this source from erroring out instead of just contributing no grants.
func hasRoleAssignmentColumns(ctx context.Context, q DBTX, dialect Dialect) (bool, error) {
	for _, col := range []string{"principal_id", "vault_id", "role"} {
		ok, err := dialect.ColumnExists(ctx, q, "role_assignments", col)
		if err != nil {
			return false, fmt.Errorf("inspect role_assignments.%s: %w", col, err)
		}
		if !ok {
			return false, nil
		}
	}
	return true, nil
}

// scanLegacyRoleAssignments walks existing role_assignments rows already
// using a legacy vault-scoped role name and emits the equivalent Azure grant
// for the same (principal, vault) via add. Rows already holding an Azure role
// name are not selected, so an operator's already-migrated or hand-made Azure
// role assignment is never re-derived from itself.
func scanLegacyRoleAssignments(ctx context.Context, q DBTX, add func(principal, vault, role, source string)) error {
	legacyNames := make([]string, 0, len(legacyRoleToAzureRole))
	for name := range legacyRoleToAzureRole {
		legacyNames = append(legacyNames, name)
	}
	sort.Strings(legacyNames) // deterministic query text, easier to debug; result set is unaffected

	placeholders := make([]string, len(legacyNames))
	args := make([]any, len(legacyNames))
	for i, name := range legacyNames {
		placeholders[i] = "?"
		args[i] = name
	}
	query := fmt.Sprintf(
		`SELECT principal_id, vault_id, role FROM role_assignments WHERE role IN (%s)`,
		strings.Join(placeholders, ","))

	rows, err := q.QueryContext(ctx, query, args...)
	if err != nil {
		return fmt.Errorf("scan legacy role_assignments: %w", err)
	}
	defer rows.Close() //nolint:errcheck
	for rows.Next() {
		var principalID, vaultID, role string
		if err := rows.Scan(&principalID, &vaultID, &role); err != nil {
			return fmt.Errorf("scan legacy role_assignments row: %w", err)
		}
		azureRole, ok := legacyRoleToAzureRole[role]
		if !ok {
			// The WHERE clause already restricts to known legacy names; this is
			// defensive only.
			continue
		}
		add(principalID, vaultID, azureRole, legacyRoleAssignmentSource)
	}
	return rows.Err()
}

// globalAdminIDs returns the ids of users holding the legacy global admin role.
// A database with no users table yields no admins rather than an error.
func globalAdminIDs(ctx context.Context, q DBTX, dialect Dialect) ([]string, error) {
	hasRole, err := dialect.ColumnExists(ctx, q, "users", "role")
	if err != nil {
		return nil, fmt.Errorf("inspect users.role: %w", err)
	}
	if !hasRole {
		return nil, nil
	}
	rows, err := q.QueryContext(ctx, `SELECT id FROM users WHERE role = ?`, model.RoleAdmin)
	if err != nil {
		return nil, fmt.Errorf("list global admins: %w", err)
	}
	defer rows.Close() //nolint:errcheck
	var out []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("scan global admin: %w", err)
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

// backfillActor is the created_by value stamped on assignments the upgrade
// migration generates. It distinguishes derived grants from operator grants in
// the audit trail.
const backfillActor = "00000000-0000-0000-0000-000000000000"

// roleBackfillAppliedKey is the audit_config marker recording that the P2
// role-assignment backfill has already run against this database. Its
// presence makes the backfill a one-time migration step rather than a
// startup-every-time scan: without it, an operator who revokes a backfilled
// grant (DELETE /api/v1/vaults/{vault}/role-assignments/{id}, the documented
// upgrade remediation path) would see it silently re-created on the next
// restart, because the ownership data that produced it hasn't changed.
const roleBackfillAppliedKey = "role_backfill_applied"

// backfillRoleAssignments materialises the plan from PlanRoleBackfill, but only
// once per deployment: it checks the roleBackfillAppliedKey marker in
// audit_config first and returns immediately, with no query and no log lines,
// if it is already set. Each insert is additionally guarded by a lookup on the
// same (principal_id, role, vault_id) tuple the table's UNIQUE constraint
// covers, so even a re-run — e.g. if the process crashes between finishing the
// grants and writing the marker — cannot create a duplicate row, only
// (narrowly, in that crash window) resurrect a grant an operator had revoked
// since the previous run.
//
// That residual crash-window risk is accepted rather than closed with a
// transaction: backfillRoleAssignments takes a plain *sql.DB, the same
// non-transactional convention every other migrateSchema step in this file
// uses (ALTER TABLE statements, seedDefaultVault, seedAuditConfig, ...), and
// wrapping only this one step in a transaction would not be atomic with the
// schema changes around it anyway — a crash could equally land between two
// ALTER TABLE calls. Exactly-once semantics across a crash aren't achievable
// here without redesigning migrateSchema's transaction model wholesale, which
// is out of scope for a one-time migration step whose worst case (a re-run
// that skips revoked grants right back in, once, only if the process dies at
// that exact instant) is already far rarer and lower-impact than the bug this
// marker fixes (guaranteed resurrection on every single restart).
//
// It runs inside migrateSchema because the fail-closed authorization introduced
// with it would otherwise lock out every existing deployment: before this
// migration no role assignment exists, and after the PolicyMiddleware inversion
// no role assignment means no access.
func (d *DBRepository) backfillRoleAssignments(db *sql.DB) error {
	ctx := context.Background()

	applied, err := d.roleBackfillApplied(db)
	if err != nil {
		return fmt.Errorf("check role backfill marker: %w", err)
	}
	if applied {
		return nil
	}

	// SetupSchema seeds the default vault after migrateSchema, but
	// role_assignments has a foreign key to vaults(id). Seed it here first; the
	// call is idempotent.
	if err := d.seedDefaultVault(db); err != nil {
		return fmt.Errorf("seed default vault before role backfill: %w", err)
	}

	grants, err := PlanRoleBackfill(ctx, NewConn(db, d.dialect), d.dialect)
	if err != nil {
		return fmt.Errorf("plan role backfill: %w", err)
	}
	if len(grants) == 0 {
		// A fresh install with no legacy ownership data still needs the
		// marker set, or every future startup would re-scan forever.
		return d.markRoleBackfillApplied(db)
	}

	created := map[string]int{}
	examined := map[string]int{}
	names := map[string]string{}
	for _, g := range grants {
		examined[g.VaultID]++
		names[g.VaultID] = g.VaultName

		var existing int
		if err := db.QueryRow(d.dialect.Rebind(
			`SELECT COUNT(*) FROM role_assignments WHERE principal_id = ? AND role = ? AND vault_id = ?`),
			g.PrincipalID, g.Role, g.VaultID).Scan(&existing); err != nil {
			return fmt.Errorf("check existing assignment for %s in %s: %w", g.PrincipalID, g.VaultID, err)
		}
		if existing > 0 {
			continue
		}
		if _, err := db.Exec(d.dialect.Rebind(
			`INSERT INTO role_assignments (id, principal_id, principal_type, role, vault_id, created_by, created_at)
			 VALUES (?, ?, ?, ?, ?, ?, ?)`),
			uuid.NewString(), g.PrincipalID, string(model.PrincipalTypeUser),
			g.Role, g.VaultID, backfillActor, time.Now().UTC(),
		); err != nil {
			return fmt.Errorf("insert backfilled assignment for %s in %s: %w", g.PrincipalID, g.VaultID, err)
		}
		created[g.VaultID]++
	}

	// One summary line per vault, so an upgrade leaves an auditable record of
	// exactly what authority it handed out.
	vaultIDs := make([]string, 0, len(examined))
	for id := range examined {
		vaultIDs = append(vaultIDs, id)
	}
	sort.Strings(vaultIDs)
	for _, id := range vaultIDs {
		d.log.Info(fmt.Sprintf(
			"Role backfill: vault=%s (%s) grants_examined=%d assignments_created=%d",
			names[id], id, examined[id], created[id]))
	}
	return d.markRoleBackfillApplied(db)
}

// roleBackfillApplied reports whether the one-time role backfill has already
// run against this database. audit_config is created unconditionally by
// createOptimizedSchema before migrateSchema (and therefore
// backfillRoleAssignments) ever runs, so the table is always present here.
func (d *DBRepository) roleBackfillApplied(db *sql.DB) (bool, error) {
	var count int
	if err := db.QueryRow(
		d.dialect.Rebind("SELECT COUNT(*) FROM audit_config WHERE key = ?"), roleBackfillAppliedKey,
	).Scan(&count); err != nil {
		return false, fmt.Errorf("failed to check audit_config key %q: %w", roleBackfillAppliedKey, err)
	}
	return count > 0, nil
}

// markRoleBackfillApplied records that the backfill has completed, so
// backfillRoleAssignments short-circuits on every subsequent startup instead
// of re-deriving and re-checking grants that may since have been revoked.
func (d *DBRepository) markRoleBackfillApplied(db *sql.DB) error {
	if _, err := db.Exec(
		d.dialect.Rebind("INSERT INTO audit_config (key, value) VALUES (?, ?)"),
		roleBackfillAppliedKey, time.Now().UTC().Format(time.RFC3339),
	); err != nil {
		return fmt.Errorf("failed to mark role backfill applied: %w", err)
	}
	return nil
}
