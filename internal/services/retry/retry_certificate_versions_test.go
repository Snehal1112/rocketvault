package retry

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/google/uuid"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"rocketvault/internal/services/certificates"
	"rocketvault/internal/services/certificates/mocks"
	"rocketvault/model"
)

func TestRetryCertificateService_VersionMethodsDelegate(t *testing.T) {
	ctx := context.Background()
	inner := mocks.NewMockCertificateService(t)
	certID := uuid.New()
	scope := model.NewVaultScope(uuid.New(), uuid.New())
	req := certificates.UpdateCertificateVersionRequest{CertID: certID, Version: 1, Scope: scope}

	inner.On("ListCertificateVersions", mock.Anything, certID, scope).
		Return([]model.CertificateVersion{{Version: 1, Current: true}}, nil)
	inner.On("GetCertificateVersion", mock.Anything, certID, 1, scope).
		Return(&model.CertificateVersion{Version: 1, Current: true}, nil)
	inner.On("UpdateCertificateVersion", mock.Anything, req).
		Return(&model.CertificateVersion{Version: 1, Current: true}, nil)

	svc := NewRetryCertificateService(inner, &noopRetryService{})

	list, err := svc.ListCertificateVersions(ctx, certID, scope)
	require.NoError(t, err)
	assert.Len(t, list, 1)
	one, err := svc.GetCertificateVersion(ctx, certID, 1, scope)
	require.NoError(t, err)
	assert.True(t, one.Current)
	updated, err := svc.UpdateCertificateVersion(ctx, req)
	require.NoError(t, err)
	assert.Equal(t, 1, updated.Version)
}

// newRealRetryService builds the real retry service with the default
// retryable substrings and short delays.
func newRealRetryService(t *testing.T) RetryService {
	t.Helper()
	v := viper.New()
	v.Set("retry.database.enabled", true)
	v.Set("retry.database.max_attempts", 3)
	v.Set("retry.database.initial_delay", "1ms")
	v.Set("retry.database.max_delay", "5ms")
	v.Set("retry.database.backoff_multiplier", 2.0)
	v.Set("retry.database.retryable_errors", []string{"connection refused", "database is locked", "timeout"})
	rs, err := NewRetryService(v)
	require.NoError(t, err)
	return rs
}

func TestRetryCertificateService_ConflictIsNotRetried(t *testing.T) {
	ctx := context.Background()
	certID := uuid.New()
	scope := model.NewVaultScope(uuid.New(), uuid.New())
	conflict := fmt.Errorf("renew: %w", model.ErrCertificateVersionConflict)

	inner := mocks.NewMockCertificateService(t)
	inner.On("RenewCertificate", mock.Anything, certID, scope, 30).Return(nil, conflict).Once()
	req := certificates.UpdateCertificateVersionRequest{CertID: certID, Version: 1, Scope: scope}
	inner.On("UpdateCertificateVersion", mock.Anything, req).Return(nil, conflict).Once()

	svc := NewRetryCertificateService(inner, newRealRetryService(t))

	_, err := svc.RenewCertificate(ctx, certID, scope, 30)
	require.Error(t, err)
	assert.True(t, errors.Is(err, model.ErrCertificateVersionConflict), "conflict identity must survive the wrapper")

	_, err = svc.UpdateCertificateVersion(ctx, req)
	require.Error(t, err)
	assert.True(t, errors.Is(err, model.ErrCertificateVersionConflict))

	// Once() plus the mock's cleanup assertion prove one call each.
	inner.AssertNumberOfCalls(t, "RenewCertificate", 1)
	inner.AssertNumberOfCalls(t, "UpdateCertificateVersion", 1)
}

func TestRetryCertificateService_TransientErrorIsRetried(t *testing.T) {
	ctx := context.Background()
	certID := uuid.New()
	scope := model.NewVaultScope(uuid.New(), uuid.New())

	inner := mocks.NewMockCertificateService(t)
	inner.On("RenewCertificate", mock.Anything, certID, scope, 30).
		Return(nil, errors.New("database is locked"))

	svc := NewRetryCertificateService(inner, newRealRetryService(t))
	_, err := svc.RenewCertificate(ctx, certID, scope, 30)
	require.Error(t, err)
	assert.Greater(t, len(inner.Calls), 1, "a retryable error must be retried, proving the retry service is live")
}
