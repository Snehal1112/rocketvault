package common

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestItemExport_SealAndOpenRoundTrip(t *testing.T) {
	content := []byte("-----BEGIN CERTIFICATE-----\nLEAF\n-----END CERTIFICATE-----\n" +
		"-----BEGIN PRIVATE KEY-----\nKEY-MATERIAL\n-----END PRIVATE KEY-----\n")
	sealed, err := SealItemExport(ItemExportPayload{
		Kind: ItemExportKindCertificate, ID: "id-1", Name: "client", Version: 2,
		Format: "pem", KeyAlgorithm: "RSA-2048", Content: content,
	}, "correct horse")
	require.NoError(t, err)
	assert.True(t, IsSealedExport(sealed))
	assert.NotContains(t, string(sealed), "KEY-MATERIAL")
	assert.NotContains(t, string(sealed), "client")

	got, err := OpenItemExport(sealed, "correct horse")
	require.NoError(t, err)
	assert.Equal(t, 1, got.PayloadVersion)
	assert.Equal(t, ItemExportKindCertificate, got.Kind)
	assert.Equal(t, "id-1", got.ID)
	assert.Equal(t, "client", got.Name)
	assert.Equal(t, 2, got.Version)
	assert.Equal(t, "pem", got.Format)
	assert.Equal(t, "RSA-2048", got.KeyAlgorithm)
	assert.Equal(t, content, got.Content)
}

func TestItemExport_WrongPassphrase(t *testing.T) {
	sealed, err := SealItemExport(ItemExportPayload{Kind: ItemExportKindKey, Content: []byte("k")}, "right")
	require.NoError(t, err)
	_, err = OpenItemExport(sealed, "wrong")
	assert.ErrorIs(t, err, ErrWrongPassphrase)
}

func TestItemExport_RefusesOtherSealedPayloads(t *testing.T) {
	for name, plain := range map[string]string{
		"secrets json":          `[{"name":"db","value":"x"}]`,
		"secrets csv":           "name,value\ndb,x\n",
		"object without marker": `{"kind":"key","content":"eA=="}`,
		"unknown kind":          `{"rocketvault_item_export":1,"kind":"secret"}`,
	} {
		sealed, err := SealExport([]byte(plain), "p")
		require.NoError(t, err)
		_, err = OpenItemExport(sealed, "p")
		assert.ErrorIs(t, err, ErrNotItemExport, name)
	}
}

func TestItemExport_RefusesANewerPayloadVersion(t *testing.T) {
	sealed, err := SealExport([]byte(`{"rocketvault_item_export":2,"kind":"key"}`), "p")
	require.NoError(t, err)
	_, err = OpenItemExport(sealed, "p")
	assert.ErrorIs(t, err, ErrUnsupportedExportVersion)
}

func TestSealItemExport_RefusesUnknownKindAndEmptyPassphrase(t *testing.T) {
	_, err := SealItemExport(ItemExportPayload{Kind: "secret"}, "p")
	assert.EqualError(t, err, `unknown item export kind "secret"`)
	_, err = SealItemExport(ItemExportPayload{Kind: ItemExportKindKey}, "")
	assert.ErrorIs(t, err, ErrPassphraseRequired)
}
