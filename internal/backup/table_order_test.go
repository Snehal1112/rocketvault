package backup

import (
	"reflect"
	"testing"
)

func TestTopologicalOrder_ParentsBeforeChildren(t *testing.T) {
	tables := []string{"secret_versions", "user_roles", "users", "secrets", "secret_tags"}
	order, err := topologicalOrder(tables)
	if err != nil {
		t.Fatal(err)
	}
	pos := make(map[string]int, len(order))
	for i, name := range order {
		pos[name] = i
	}
	if pos["users"] > pos["user_roles"] {
		t.Fatalf("users must come before user_roles, got order %v", order)
	}
	if pos["secrets"] > pos["secret_versions"] {
		t.Fatalf("secrets must come before secret_versions, got order %v", order)
	}
	if pos["secrets"] > pos["secret_tags"] {
		t.Fatalf("secrets must come before secret_tags, got order %v", order)
	}
}

func TestTopologicalOrder_TableWithTwoParents(t *testing.T) {
	tables := []string{"secret_policies", "secrets", "rotation_policies", "users"}
	order, err := topologicalOrder(tables)
	if err != nil {
		t.Fatal(err)
	}
	pos := make(map[string]int, len(order))
	for i, name := range order {
		pos[name] = i
	}
	if pos["secrets"] > pos["secret_policies"] {
		t.Fatalf("secrets must come before secret_policies, got order %v", order)
	}
	if pos["rotation_policies"] > pos["secret_policies"] {
		t.Fatalf("rotation_policies must come before secret_policies, got order %v", order)
	}
}

func TestTopologicalOrder_UnknownTableTreatedAsRoot(t *testing.T) {
	// A table present in the input but absent from tableDependencies (e.g. a
	// brand-new table nobody has updated the map for yet) must not error --
	// it's treated as having no dependencies, sorting first. The Task 3
	// drift-guard test is what catches this staleness; topologicalOrder
	// itself must stay defensive, not panic or fail the whole restore.
	tables := []string{"users", "some_future_table"}
	order, err := topologicalOrder(tables)
	if err != nil {
		t.Fatal(err)
	}
	if len(order) != 2 {
		t.Fatalf("expected both tables in output, got %v", order)
	}
}

func TestTopologicalOrder_OnlyIncludesInputTables(t *testing.T) {
	// tableDependencies knows about many more tables than this small input
	// list -- the output must never include a table the caller didn't ask
	// for (e.g. a live SQLite DB mid-migration might not have every table
	// tableDependencies eventually needs to know about).
	tables := []string{"users", "secrets"}
	order, err := topologicalOrder(tables)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(sortedCopy(order), sortedCopy([]string{"users", "secrets"})) {
		t.Fatalf("expected exactly {users, secrets}, got %v", order)
	}
}

func TestTopologicalOrder_Deterministic(t *testing.T) {
	tables := []string{"key_rotation_policies", "keys", "users", "key_versions", "key_tags"}
	first, err := topologicalOrder(tables)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ {
		again, err := topologicalOrder(tables)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(first, again) {
			t.Fatalf("topologicalOrder must be deterministic across calls; got %v then %v", first, again)
		}
	}
}

func sortedCopy(s []string) []string {
	out := make([]string, len(s))
	copy(out, s)
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j-1] > out[j]; j-- {
			out[j-1], out[j] = out[j], out[j-1]
		}
	}
	return out
}
