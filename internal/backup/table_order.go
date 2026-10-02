package backup

import (
	"fmt"
	"sort"
)

// tableDependencies maps each table to the tables it holds a foreign key to
// (its parents). Restoring data must create parents before children;
// clearing data must remove children before parents, or Postgres's enforced
// FK constraints reject the operation mid-transaction (SQLite's foreign_keys
// pragma is off by default, which is what let this bug ship unnoticed --
// see Critical Finding #9, docs/plans/2026-08-18-azure-keyvault-parity-audit.md).
//
// Derived directly from every FOREIGN KEY clause in
// internal/db/db.go's createOptimizedSchema. Task 3's drift-guard test
// cross-checks this map against the live database's real FK constraints on
// every test run -- if this map goes stale after a schema change, that test
// fails, not a production restore.
var tableDependencies = map[string][]string{
	"users":                     {},
	"vaults":                    {},
	"bootstrap_tokens":          {},
	"audit_logs":                {},
	"access_policies":           {},
	"oauth2_clients":            {},
	"vault_provisioning_grants": {},
	"audit_config":              {},
	"login_failures":            {},
	"secrets":                   {"users"},
	"keys":                      {"users"},
	"certificates":              {"users"},
	"crl":                       {"users"},
	"rotation_policies":         {"users"},
	"user_sessions":             {"users"},
	"user_roles":                {"users"},
	"role_assignments":          {"vaults"},
	"vault_webhook_configs":     {"vaults"},
	"key_tags":                  {"keys"},
	"key_versions":              {"keys"},
	"certificate_tags":          {"certificates"},
	"certificate_versions":      {"certificates"},
	"certificate_policies":      {"certificates", "users"},
	"key_rotation_policies":     {"keys", "users"},
	"secret_tags":               {"secrets"},
	"secret_versions":           {"secrets", "users"},
	"secret_rotation_history":   {"secrets", "rotation_policies"},
	"rotation_reminders":        {"secrets", "rotation_policies"},
	"secret_policies":           {"secrets", "rotation_policies"},
}

// topologicalOrder returns tables ordered so every table appears after all
// tables it depends on (parents before children) -- the correct order for
// INSERT during a restore. Reverse the result for DELETE. Only tables
// present in the tables argument are included in the output. A table
// present in tables but absent from tableDependencies is treated as having
// no dependencies (sorts first) rather than erroring -- a defensive
// fallback; Task 3's drift-guard test is the real check for this staleness.
func topologicalOrder(tables []string) ([]string, error) {
	present := make(map[string]bool, len(tables))
	for _, t := range tables {
		present[t] = true
	}

	var order []string
	const (
		unvisited = 0
		inFlight  = 1
		done      = 2
	)
	visited := make(map[string]int)
	var visit func(t string) error
	visit = func(t string) error {
		switch visited[t] {
		case done:
			return nil
		case inFlight:
			return fmt.Errorf("circular table dependency detected at %q", t)
		}
		visited[t] = inFlight
		for _, parent := range tableDependencies[t] {
			if !present[parent] {
				continue
			}
			if err := visit(parent); err != nil {
				return err
			}
		}
		visited[t] = done
		order = append(order, t)
		return nil
	}

	// Sort input first for deterministic traversal order -- map iteration
	// order is not stable, and DFS visit order affects the output.
	sorted := make([]string, len(tables))
	copy(sorted, tables)
	sort.Strings(sorted)

	for _, t := range sorted {
		if err := visit(t); err != nil {
			return nil, err
		}
	}
	return order, nil
}
