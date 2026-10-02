package retry

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"rocketvault/internal/services/keys/mocks"
	"rocketvault/model"
)

func TestRetryExportKey_IsNotRetried(t *testing.T) {
	inner := mocks.NewMockKeyService(t)
	scope := model.NewVaultScope(uuid.New(), uuid.New())
	id := uuid.New()
	inner.On("ExportKey", mock.Anything, scope, id, 0).Return(nil, errors.New("database is locked")).Once()

	svc := NewRetryKeyService(inner, failingRetryService{})
	_, err := svc.ExportKey(context.Background(), scope, id, 0)
	require.Error(t, err)
	inner.AssertNumberOfCalls(t, "ExportKey", 1)
}
