package repositories_test

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"rocketvault/model"
)

// archiveOneVersion renews cert once, so it has one archived row.
func archiveOneVersion(t *testing.T, cert *model.Certificate, archive func(model.CertificateVersionRecord, *model.Certificate, model.Scope) error) {
	t.Helper()
	require.NoError(t, archive(cert.ArchiveRecord(), renewedFrom(cert, "PEM-v2"), model.NewVaultScope(cert.VaultID, cert.UserID)))
}

func TestCertificatePurge_RemovesVersionRows(t *testing.T) {
	certs, versions, raw := newCertVersionFixture(t)
	ctx := context.Background()
	cert := seedVersionedCert(t, certs, uuid.New())
	archiveOneVersion(t, cert, func(a model.CertificateVersionRecord, r *model.Certificate, s model.Scope) error {
		return versions.ArchiveAndRenew(ctx, a, r, s)
	})

	require.NoError(t, certs.SoftDelete(ctx, cert.ID))
	require.NoError(t, certs.PurgeCertificate(ctx, cert.ID))
	assert.Zero(t, countCertVersions(t, raw, cert.ID), "SQLite does not cascade; purge must delete version rows itself")
}

func TestCertificateDelete_RemovesVersionRows(t *testing.T) {
	certs, versions, raw := newCertVersionFixture(t)
	ctx := context.Background()
	cert := seedVersionedCert(t, certs, uuid.New())
	archiveOneVersion(t, cert, func(a model.CertificateVersionRecord, r *model.Certificate, s model.Scope) error {
		return versions.ArchiveAndRenew(ctx, a, r, s)
	})

	require.NoError(t, certs.Delete(ctx, cert.ID))
	assert.Zero(t, countCertVersions(t, raw, cert.ID))
}

func TestCertificatePurgeVaultContents_RemovesOnlyThatVaultsVersionRows(t *testing.T) {
	certs, versions, raw := newCertVersionFixture(t)
	ctx := context.Background()
	purged := seedVersionedCert(t, certs, uuid.New())
	kept := seedVersionedCert(t, certs, uuid.New())
	for _, c := range []*model.Certificate{purged, kept} {
		archiveOneVersion(t, c, func(a model.CertificateVersionRecord, r *model.Certificate, s model.Scope) error {
			return versions.ArchiveAndRenew(ctx, a, r, s)
		})
	}

	purger, ok := certs.(interface {
		PurgeVaultContents(ctx context.Context, vaultID uuid.UUID) error
	})
	require.True(t, ok, "the real certificate repository purges vault contents")
	require.NoError(t, purger.PurgeVaultContents(ctx, purged.VaultID))

	assert.Zero(t, countCertVersions(t, raw, purged.ID))
	assert.Equal(t, 1, countCertVersions(t, raw, kept.ID), "another vault's history must survive")
}

func TestCertificateSoftDeleteAndRecover_KeepVersionRows(t *testing.T) {
	certs, versions, raw := newCertVersionFixture(t)
	ctx := context.Background()
	cert := seedVersionedCert(t, certs, uuid.New())
	archiveOneVersion(t, cert, func(a model.CertificateVersionRecord, r *model.Certificate, s model.Scope) error {
		return versions.ArchiveAndRenew(ctx, a, r, s)
	})

	require.NoError(t, certs.SoftDelete(ctx, cert.ID))
	assert.Equal(t, 1, countCertVersions(t, raw, cert.ID))
	require.NoError(t, certs.RecoverCertificate(ctx, cert.ID))
	assert.Equal(t, 1, countCertVersions(t, raw, cert.ID))
}
