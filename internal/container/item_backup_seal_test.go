package container

import (
	"bytes"
	"context"
	"encoding/base64"
	"testing"

	"github.com/google/uuid"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"

	"rocketvault/internal/backup"
)

// TestItemBackupService_SealedWhenMasterKeyConfigured pins the container
// wiring for B76. Only a service with its seal key set reports an unsealed
// blob as unsealed; an unwired one reports ErrSealKeyUnset instead.
func TestItemBackupService_SealedWhenMasterKeyConfigured(t *testing.T) {
	orig := viper.GetString("master_key")
	t.Cleanup(func() { viper.Set("master_key", orig) })
	viper.Set("master_key", base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x24}, 32)))

	c, err := NewServiceContainer(newMinimalConfig(t))
	require.NoError(t, err)
	t.Cleanup(func() { _ = c.Close() })

	err = c.GetItemBackupService().RestoreSecret(context.Background(), "not-a-sealed-blob", uuid.New(), uuid.New(), uuid.New())
	require.ErrorIs(t, err, backup.ErrUnsealedBlob)
}

// TestItemBackupService_FailsClosedWithoutMasterKey pins the other half of
// the wiring: with no usable master key the container still starts, but
// item backup and restore refuse to run instead of using the unauthenticated
// format.
func TestItemBackupService_FailsClosedWithoutMasterKey(t *testing.T) {
	orig := viper.GetString("master_key")
	t.Cleanup(func() { viper.Set("master_key", orig) })
	viper.Set("master_key", "")

	c, err := NewServiceContainer(newMinimalConfig(t))
	require.NoError(t, err)
	t.Cleanup(func() { _ = c.Close() })

	err = c.GetItemBackupService().RestoreSecret(context.Background(), "not-a-sealed-blob", uuid.New(), uuid.New(), uuid.New())
	require.ErrorIs(t, err, backup.ErrSealKeyUnset)
}
