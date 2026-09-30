package model_test

import (
	"encoding/json"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"rocketvault/model"
)

func TestCertificate_CurrentVersionDefaultsToOne(t *testing.T) {
	assert.Equal(t, 1, (&model.Certificate{}).CurrentVersion(), "a row that predates versioning is version 1")
	assert.Equal(t, 4, (&model.Certificate{Version: 4}).CurrentVersion())
}

func TestCertificate_ArchiveRecordSnapshotsMaterialAndLifecycle(t *testing.T) {
	expires := time.Now().Add(time.Hour)
	notBefore := time.Now().Add(-time.Hour)
	cert := &model.Certificate{
		ID: uuid.New(), KeyID: uuid.New(), Certificate: "PEM", PrivateKey: "ENC",
		CreatedAt: time.Now(), ExpiresAt: &expires, NotBefore: &notBefore, Enabled: true, Version: 3,
	}

	rec := cert.ArchiveRecord()
	assert.Equal(t, cert.ID, rec.CertificateID)
	assert.Equal(t, 3, rec.Version)
	assert.Equal(t, "PEM", rec.Certificate)
	assert.Equal(t, "ENC", rec.PrivateKey)
	assert.Equal(t, cert.KeyID, rec.KeyID)
	assert.True(t, rec.Enabled)

	// The snapshot must not share time pointers with the live row.
	original := *cert.ExpiresAt
	*cert.ExpiresAt = original.Add(time.Hour)
	assert.Equal(t, original, *rec.ExpiresAt)

	meta := rec.Metadata()
	assert.False(t, meta.Current)
	assert.Equal(t, 3, meta.Version)
}

func TestCertificate_VersionMetadataIsCurrent(t *testing.T) {
	cert := &model.Certificate{ID: uuid.New(), Enabled: true, Version: 2}
	meta := cert.VersionMetadata()
	assert.True(t, meta.Current)
	assert.Equal(t, 2, meta.Version)
	assert.Equal(t, cert.ID, meta.CertificateID)
}

// TestCertificateVersion_HasNoMaterialFields pins the rule that the metadata
// type can never carry a PEM or a key, because handlers encode it directly.
func TestCertificateVersion_HasNoMaterialFields(t *testing.T) {
	typ := reflect.TypeOf(model.CertificateVersion{})
	for i := 0; i < typ.NumField(); i++ {
		assert.NotContains(t, []string{"Certificate", "PrivateKey", "PEM", "Value"}, typ.Field(i).Name)
	}
	body, err := json.Marshal(model.CertificateVersion{Version: 1, Enabled: true})
	require.NoError(t, err)
	assert.NotContains(t, string(body), "private_key")
	assert.NotContains(t, string(body), `"certificate"`)
}

func TestValidateCertificateVersionWindow(t *testing.T) {
	early := time.Now()
	late := early.Add(time.Hour)

	assert.NoError(t, model.ValidateCertificateVersionWindow(nil, nil))
	assert.NoError(t, model.ValidateCertificateVersionWindow(&early, nil))
	assert.NoError(t, model.ValidateCertificateVersionWindow(nil, &late))
	assert.NoError(t, model.ValidateCertificateVersionWindow(&early, &late))

	err := model.ValidateCertificateVersionWindow(&late, &early)
	require.Error(t, err)
	assert.True(t, errors.Is(err, model.ErrInvalidCertificateVersionAttributes))
}

func TestCertificate_VersionUsable_DisabledParentGatesEveryVersion(t *testing.T) {
	v := model.CertificateVersion{Version: 1, Enabled: true}
	assert.True(t, (&model.Certificate{Enabled: true}).VersionUsable(v))
	assert.False(t, (&model.Certificate{Enabled: false}).VersionUsable(v))

	past := time.Now().Add(-time.Hour)
	expired := model.CertificateVersion{Version: 1, Enabled: true, ExpiresAt: &past}
	assert.False(t, (&model.Certificate{Enabled: true}).VersionUsable(expired))
}
