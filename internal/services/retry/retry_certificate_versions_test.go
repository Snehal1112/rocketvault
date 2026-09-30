package retry

import (
	"context"
	"testing"

	"github.com/google/uuid"
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
