package model_test

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"rocketvault/model"
)

func TestExportable_JSONTag(t *testing.T) {
	body, err := json.Marshal(model.Certificate{Exportable: true})
	require.NoError(t, err)
	assert.Contains(t, string(body), `"exportable":true`)

	body, err = json.Marshal(model.Key{Exportable: true})
	require.NoError(t, err)
	assert.Contains(t, string(body), `"exportable":true`)
}

func TestCertificateClone_CopiesExportable(t *testing.T) {
	c := &model.Certificate{Exportable: true}
	assert.True(t, c.Clone().Exportable, "the cache clones certificates, so the flag must survive Clone")
}

func TestKey_KeyAlgorithm(t *testing.T) {
	cases := map[string]model.Key{
		"RSA-2048": {Type: model.KeyTypeRSA, Bits: 2048},
		"RSA-4096": {Type: model.KeyTypeRSA, Bits: 4096},
		"RSA":      {Type: model.KeyTypeRSA},
		"EC-P256":  {Type: model.KeyTypeECDSA, Curve: "P-256"},
		"EC-P521":  {Type: model.KeyTypeECDSA, Curve: "P-521"},
		"EC":       {Type: model.KeyTypeECDSA},
		"EC-P256K": {Type: model.KeyTypeES256K, Curve: "P-256K"},
		"oct-256":  {Type: model.KeyTypeOct, Bits: 256},
	}
	for want, key := range cases {
		k := key
		assert.Equal(t, want, k.KeyAlgorithm())
	}
}

func TestExportSentinels_AreDistinct(t *testing.T) {
	assert.NotEqual(t, model.ErrExportableKeyRequired, model.ErrExportableNotSupported)
	assert.Contains(t, model.ErrExportableKeyRequired.Error(), "exportable")
}
