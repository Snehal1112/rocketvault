package certificates

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// The help text claimed renewal always self-signs, which was true and is the
// bug (B37). It must now describe the CA-preserving behavior.
func TestRenewCmd_LongDescribesCAPreservation(t *testing.T) {
	long := renewCmd.Long

	require.NotContains(t, long, "always self-signed",
		"renewal no longer converts a CA-signed certificate to self-signed")
	require.Contains(t, long, "re-issued through that same CA")
	require.Contains(t, long, "Microsoft.KeyVault/vaults/certificates/create",
		"the required data action must stay named in full")

	// Every Long line stays within the 78-column house limit.
	for _, line := range strings.Split(long, "\n") {
		require.LessOrEqual(t, len(line), 78, "line over 78 columns: %q", line)
	}
}

// Renewal keeps the certificate ID and adds a version, so there is exactly
// one certificate ID to print.
func TestRenewCmd_LongDoesNotPromiseANewID(t *testing.T) {
	require.Contains(t, renewCmd.Long, "There is no new certificate ID",
		"the help must say the ID does not change")
}

// Renewal adds a version and keeps the old one, and the help must say so.
func TestRenewCmd_LongDescribesVersioning(t *testing.T) {
	require.Contains(t, renewCmd.Long, "new version")
	require.Contains(t, renewCmd.Long, "certificate versions list")
	require.NotContains(t, renewCmd.Long, "written in place")
}
