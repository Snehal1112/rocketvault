package vaultcli

import (
	"bytes"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/uuid"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"rocketvault/common"
)

func TestExportOutput_WriteSealFailureWritesNothing(t *testing.T) {
	cmd := &cobra.Command{}
	cmd.SetErr(&bytes.Buffer{})
	o := ExportOutput{File: filepath.Join(t.TempDir(), "k.sealed"), Encrypt: true}
	payload := common.ItemExportPayload{Kind: common.ItemExportKindKey, ID: "id", Name: "signer", Version: 1,
		Format: "pem", Content: []byte("KEY-MATERIAL")}

	// An empty passphrase makes the seal itself fail.
	err := o.Write(cmd, payload, "", "unused")
	require.ErrorIs(t, err, ErrExportNotSealed)
	assert.ErrorIs(t, err, common.ErrPassphraseRequired)
	_, statErr := os.Stat(o.File)
	assert.ErrorIs(t, statErr, fs.ErrNotExist)
}

func TestExportAttempt_FailOutputSealFailureHasItsOwnReason(t *testing.T) {
	rec := &exportAuditRecorder{}
	var logs bytes.Buffer
	s, _ := exportSession(t, rec, &logs)

	err := BeginExportAttempt(s, "certificate", uuid.NewString(), "pem", 0).
		FailOutput(fmt.Errorf("%w: seal-cause-detail", ErrExportNotSealed))
	assert.EqualError(t, err, "failed to export certificate: internal error; see the RocketVault log for details")
	require.Len(t, rec.events, 1)
	assert.Contains(t, rec.events[0].Details, `"code":"internal_error"`)
	assert.Contains(t, rec.events[0].Details, `"reason":"the export could not be sealed"`)
	assert.NotContains(t, rec.events[0].Details, "could not be written")
	assert.NotContains(t, rec.events[0].Details, "seal-cause-detail")
	assert.Contains(t, logs.String(), "seal-cause-detail", "the cause goes to the log file only")
}
