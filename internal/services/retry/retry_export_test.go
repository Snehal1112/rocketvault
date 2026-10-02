package retry

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	internalRetry "rocketvault/internal/retry"
	"rocketvault/internal/services/certificates"
	"rocketvault/internal/services/certificates/mocks"
	"rocketvault/model"
)

// failingRetryService retries every operation three times, the way a real
// policy does on a retryable error. A method routed through it would run
// three times on failure; a pass-through method runs once.
type failingRetryService struct{}

func (failingRetryService) run(op func() error) error {
	var err error
	for i := 0; i < 3; i++ {
		if err = op(); err == nil {
			return nil
		}
	}
	return err
}
func (f failingRetryService) ExecuteDatabaseOperation(_ context.Context, op func() error) error {
	return f.run(op)
}
func (f failingRetryService) ExecuteExternalServiceOperation(_ context.Context, op func() error) error {
	return f.run(op)
}
func (f failingRetryService) ExecuteServiceOperation(_ context.Context, op func() error) error {
	return f.run(op)
}
func (f failingRetryService) ExecuteInteractiveOperation(_ context.Context, op func() error) error {
	return f.run(op)
}
func (failingRetryService) GetDatabasePolicy() internalRetry.Policy { return internalRetry.Policy{} }
func (failingRetryService) GetExternalServicesPolicy() internalRetry.Policy {
	return internalRetry.Policy{}
}
func (failingRetryService) GetServiceOperationsPolicy() internalRetry.Policy {
	return internalRetry.Policy{}
}
func (failingRetryService) GetInteractivePolicy() internalRetry.Policy { return internalRetry.Policy{} }

func TestRetryExportCertificate_IsNotRetried(t *testing.T) {
	inner := mocks.NewMockCertificateService(t)
	scope := model.NewVaultScope(uuid.New(), uuid.New())
	id := uuid.New()
	req := certificates.ExportCertificateRequest{Format: model.ExportFormatPEM}
	inner.On("ExportCertificate", mock.Anything, scope, id, req).Return(nil, errors.New("database is locked")).Once()

	svc := NewRetryCertificateService(inner, failingRetryService{})
	_, err := svc.ExportCertificate(context.Background(), scope, id, req)
	require.Error(t, err)
	inner.AssertNumberOfCalls(t, "ExportCertificate", 1)
}
