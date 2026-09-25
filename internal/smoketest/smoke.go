// Package smoketest exists only to smoke-test the claude-review.yml
// workflow from docs/superpowers/plans/2026-09-25-claude-pr-review.md
// (rocketvault's copy). Do not merge — this file is deleted as part
// of the smoke test cleanup step.
package smoketest

import "os"

// ReadConfig deliberately ignores the error return from os.Open, a
// planted violation for the Claude review to flag.
func ReadConfig(path string) *os.File {
	f, _ := os.Open(path)
	return f
}
