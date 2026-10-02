package secrets

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"rocketvault/model"
)

func TestReportRemoteImport_FailuresPrintDetailsAndReturnError(t *testing.T) {
	var out bytes.Buffer
	err := reportRemoteImport(&out, &model.ImportResponse{
		ImportedCount: 1,
		SkippedCount:  0,
		FailedCount:   2,
		TotalCount:    3,
		Errors:        []string{"Invalid 'a': bad", "Invalid 'b': bad"},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "2 record(s) failed to import")
	assert.Contains(t, out.String(), "Failed: 2")
	assert.Contains(t, out.String(), "  - Invalid 'a': bad")
	assert.Contains(t, out.String(), "  - Invalid 'b': bad")
	assert.NotContains(t, out.String(), "imported successfully")
}

func TestReportRemoteImport_CleanRunReturnsNil(t *testing.T) {
	var out bytes.Buffer
	err := reportRemoteImport(&out, &model.ImportResponse{ImportedCount: 2, TotalCount: 2})
	require.NoError(t, err)
	assert.Equal(t, "Secrets imported successfully\nImported: 2\nSkipped: 0\nFailed: 0\nTotal: 2\n", out.String())
}
