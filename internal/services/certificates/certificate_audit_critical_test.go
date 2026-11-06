package certificates

// Audit-first tests: an export must not release material and a purge must not
// remove a certificate unless the critical audit row was written first.

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"rocketvault/internal/repositories"
	auditServices "rocketvault/internal/services/audit"
	"rocketvault/model"
)

// fakeCertAudit records calls in order and can fail critical writes.
// internal/testutils cannot be used here because it imports this package.
type fakeCertAudit struct {
	mu          sync.Mutex
	criticalErr error
	calls       []string
	critical    []auditServices.AuditEvent
}

func (f *fakeCertAudit) RecordEvent(_ context.Context, ev auditServices.AuditEvent) error {
	f.note("event:" + ev.Outcome)
	return nil
}

func (f *fakeCertAudit) RecordCritical(_ context.Context, ev auditServices.AuditEvent) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, "critical:"+ev.Outcome)
	f.critical = append(f.critical, ev)
	return f.criticalErr
}

func (f *fakeCertAudit) PersistAudit(_, _, _ string) error { return nil }

func (f *fakeCertAudit) note(call string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, call)
}

// requireCertAuditUnavailable checks the public error shape of a refused operation.
func requireCertAuditUnavailable(t *testing.T, err error) {
	t.Helper()
	require.Error(t, err)
	assert.True(t, errors.Is(err, auditServices.ErrAuditUnavailable), "%v", err)
	assert.Equal(t, "audit unavailable", err.Error(), "the cause must not reach the caller")
}

// auditedCertService builds a certificate service over h's repositories with audit wired.
func auditedCertService(h *versioningHarness, audit auditServices.AuditServiceInterface) CertificateService {
	return NewCertificateService(CertificateServiceConfig{CertificateRepository: h.certRepo, KeyRepository: h.keyRepo,
		VersionRepository: h.versions, Logger: newTestCertLogger(), AuditService: audit})
}

func TestExportCertificate_AuditFailureReleasesNoMaterial(t *testing.T) {
	h := newVersioningHarness(t)
	id := createExportable(t, h, "audit-down", "RSA")
	audit := &fakeCertAudit{criticalErr: errors.New("pq: disk full on audit_logs")}

	for _, format := range []string{model.ExportFormatPEM, model.ExportFormatPKCS12} {
		res, err := auditedCertService(h, audit).ExportCertificate(context.Background(), h.scope(), id,
			ExportCertificateRequest{Format: format, Password: strPtr("pw")})
		requireCertAuditUnavailable(t, err)
		assert.Nil(t, res, "no certificate or key material may be returned")
	}
	require.Len(t, audit.critical, 2)
	assert.Equal(t, "export_certificate", audit.critical[0].Action)
	assert.Equal(t, "attempt", audit.critical[0].Outcome)
	assert.Equal(t, id.String(), audit.critical[0].ResourceID)
}

func TestExportCertificate_WritesAttemptBeforeRelease(t *testing.T) {
	h := newVersioningHarness(t)
	id := createExportable(t, h, "audit-up", "RSA")
	audit := &fakeCertAudit{}

	res, err := auditedCertService(h, audit).ExportCertificate(context.Background(), h.scope(), id,
		ExportCertificateRequest{Format: model.ExportFormatPEM})

	require.NoError(t, err)
	assert.NotEmpty(t, res.PrivateKeyPEM)
	assert.Equal(t, []string{"critical:attempt"}, audit.calls, "the result row is exportaudit's job")
	assert.Equal(t, "certificate", audit.critical[0].ResourceType)
	assert.Contains(t, audit.critical[0].Details, `"format":"pem"`)
}

// TestExportCertificate_RefusalIsNotCritical pins that a not-exportable
// denial is answered as before, even with audit down.
func TestExportCertificate_RefusalIsNotCritical(t *testing.T) {
	h := newVersioningHarness(t)
	id := h.createCert(t, "plain")
	audit := &fakeCertAudit{criticalErr: errors.New("down")}

	_, err := auditedCertService(h, audit).ExportCertificate(context.Background(), h.scope(), id,
		ExportCertificateRequest{Format: model.ExportFormatPEM})

	assert.ErrorIs(t, err, model.ErrCertificateNotExportable)
	assert.Empty(t, audit.critical)
}

// purgeableCertRepo returns a mock repository holding certID as soft-deleted in scope.
func purgeableCertRepo(scope model.Scope, certID uuid.UUID) *mockCertRepository {
	now := time.Now()
	repo := &mockCertRepository{}
	repo.On("List", mock.Anything, scope, repositories.CertificateFilter{OnlyDeleted: true}).
		Return([]model.Certificate{{ID: certID, Name: "cert", DeletedAt: &now}}, nil)
	return repo
}

func TestPurgeCertificate_AuditFailureLeavesCertSoftDeleted(t *testing.T) {
	scope := model.NewVaultScope(uuid.New(), uuid.New())
	certID := uuid.New()
	repo := purgeableCertRepo(scope, certID)
	audit := &fakeCertAudit{criticalErr: errors.New("down")}
	svc := NewCertificateService(CertificateServiceConfig{CertificateRepository: repo, Logger: newTestCertLogger(), AuditService: audit})

	err := svc.PurgeCertificate(context.Background(), certID, scope)

	requireCertAuditUnavailable(t, err)
	repo.AssertNotCalled(t, "PurgeCertificate", mock.Anything, mock.Anything)
}

func TestPurgeCertificate_WritesAttemptBeforePurge(t *testing.T) {
	scope := model.NewVaultScope(uuid.New(), uuid.New())
	certID := uuid.New()
	repo := purgeableCertRepo(scope, certID)
	audit := &fakeCertAudit{}
	repo.On("PurgeCertificate", mock.Anything, certID).Run(func(mock.Arguments) { audit.note("purge") }).Return(nil)
	svc := NewCertificateService(CertificateServiceConfig{CertificateRepository: repo, Logger: newTestCertLogger(), AuditService: audit})

	require.NoError(t, svc.PurgeCertificate(context.Background(), certID, scope))

	assert.Equal(t, []string{"critical:attempt", "purge", "event:success"}, audit.calls)
	assert.Equal(t, "purge_certificate", audit.critical[0].Action)
	assert.Equal(t, certID.String(), audit.critical[0].ResourceID)
}
