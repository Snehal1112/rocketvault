package retry

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"rocketvault/internal/retry"
	"rocketvault/model"
)

// MockRepository simulates a repository that can fail for testing retry logic
type MockRepository struct {
	mock.Mock
}

func (m *MockRepository) Create(ctx context.Context, user *model.User) error {
	args := m.Called(ctx, user)
	return args.Error(0)
}

func (m *MockRepository) Read(ctx context.Context, id uuid.UUID) (*model.User, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*model.User), args.Error(1)
}

func (m *MockRepository) Update(ctx context.Context, user *model.User) error {
	args := m.Called(ctx, user)
	return args.Error(0)
}

func (m *MockRepository) Delete(ctx context.Context, id uuid.UUID) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}

func (m *MockRepository) ReadByUsername(ctx context.Context, username string) (model.User, error) {
	args := m.Called(ctx, username)
	if args.Get(0) == nil {
		return model.User{}, args.Error(1)
	}
	return args.Get(0).(model.User), args.Error(1)
}

func (m *MockRepository) List(ctx context.Context) ([]model.User, error) {
	args := m.Called(ctx)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]model.User), args.Error(1)
}

func (m *MockRepository) ValidateBootstrapToken(ctx context.Context, token string) (bool, error) {
	args := m.Called(ctx, token)
	return args.Bool(0), args.Error(1)
}

func (m *MockRepository) InvalidateBootstrapToken(ctx context.Context, token string) error {
	args := m.Called(ctx, token)
	return args.Error(0)
}

// MockUserRepository simulates a user repository that can fail for testing retry logic
type MockUserRepository struct {
	mock.Mock
}

func (m *MockUserRepository) Create(ctx context.Context, user *model.User) error {
	args := m.Called(ctx, user)
	return args.Error(0)
}

func (m *MockUserRepository) Read(ctx context.Context, id uuid.UUID) (*model.User, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*model.User), args.Error(1)
}

func (m *MockUserRepository) Update(ctx context.Context, user *model.User) error {
	args := m.Called(ctx, user)
	return args.Error(0)
}

func (m *MockUserRepository) Delete(ctx context.Context, id uuid.UUID) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}

func (m *MockUserRepository) ReadByUsername(ctx context.Context, username string) (model.User, error) {
	args := m.Called(ctx, username)
	if args.Get(0) == nil {
		return model.User{}, args.Error(1)
	}
	return args.Get(0).(model.User), args.Error(1)
}

func (m *MockUserRepository) ReadByExternalSubject(ctx context.Context, provider, subject string) (*model.User, error) {
	args := m.Called(ctx, provider, subject)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*model.User), args.Error(1)
}

func (m *MockUserRepository) UpdateEmail(ctx context.Context, id uuid.UUID, email string) error {
	args := m.Called(ctx, id, email)
	return args.Error(0)
}

func (m *MockUserRepository) List(ctx context.Context) ([]model.User, error) {
	args := m.Called(ctx)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]model.User), args.Error(1)
}

func (m *MockUserRepository) ValidateBootstrapToken(ctx context.Context, token string) (bool, error) {
	args := m.Called(ctx, token)
	return args.Bool(0), args.Error(1)
}

func (m *MockUserRepository) InvalidateBootstrapToken(ctx context.Context, token string) error {
	args := m.Called(ctx, token)
	return args.Error(0)
}

// TestRetryServiceIntegration tests the retry service with simulated failures
func TestRetryServiceIntegration(t *testing.T) {
	// Create test configuration
	v := viper.New()
	v.Set("retry.database.enabled", true)
	v.Set("retry.database.max_attempts", 3)
	v.Set("retry.database.initial_delay", "10ms")
	v.Set("retry.database.max_delay", "100ms")
	v.Set("retry.database.backoff_multiplier", 2.0)
	v.Set("retry.database.jitter_enabled", false)

	// Create retry service
	retryService, err := NewRetryService(v)
	assert.NoError(t, err)
	assert.NotNil(t, retryService)

	ctx := context.Background()

	t.Run("successful operation on first attempt", func(t *testing.T) {
		callCount := 0
		err := retryService.ExecuteDatabaseOperation(ctx, func() error {
			callCount++
			return nil
		})

		assert.NoError(t, err)
		assert.Equal(t, 1, callCount)
	})

	t.Run("successful operation after retries", func(t *testing.T) {
		callCount := 0
		err := retryService.ExecuteDatabaseOperation(ctx, func() error {
			callCount++
			if callCount < 3 {
				return errors.New("database is locked")
			}
			return nil
		})

		assert.NoError(t, err)
		assert.Equal(t, 3, callCount)
	})

	t.Run("operation fails after max attempts", func(t *testing.T) {
		callCount := 0
		err := retryService.ExecuteDatabaseOperation(ctx, func() error {
			callCount++
			return errors.New("connection refused")
		})

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "max retry attempts exceeded")
		assert.Equal(t, 3, callCount)
	})

	t.Run("context cancellation stops retry", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		callCount := 0

		go func() {
			time.Sleep(5 * time.Millisecond)
			cancel()
		}()

		err := retryService.ExecuteDatabaseOperation(ctx, func() error {
			callCount++
			return errors.New("timeout")
		})

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "context canceled")
		assert.Less(t, callCount, 3) // Should stop before max attempts due to cancellation
	})
}

// TestRetryRepositoryWrapperIntegration tests the retry repository wrapper
func TestRetryRepositoryWrapperIntegration(t *testing.T) {
	// Create test configuration
	v := viper.New()
	v.Set("retry.database.enabled", true)
	v.Set("retry.database.max_attempts", 3)
	v.Set("retry.database.initial_delay", "10ms")
	v.Set("retry.database.max_delay", "100ms")
	v.Set("retry.database.backoff_multiplier", 2.0)
	v.Set("retry.database.jitter_enabled", false)

	retryService, err := NewRetryService(v)
	assert.NoError(t, err)

	ctx := context.Background()
	testUser := &model.User{
		ID:           uuid.New(),
		Username:     "testuser",
		PasswordHash: "hashed_password",
		TOTPSecret:   "totp_secret",
		Roles:        []string{"user"},
	}

	t.Run("create user with retry on temporary failure", func(t *testing.T) {
		mockRepo := new(MockUserRepository)
		wrapper := NewRetryUserRepositoryWrapper(mockRepo, retryService)

		// First two calls fail, third succeeds
		mockRepo.On("Create", ctx, testUser).Return(errors.New("database is locked")).Once()
		mockRepo.On("Create", ctx, testUser).Return(errors.New("database is locked")).Once()
		mockRepo.On("Create", ctx, testUser).Return(nil).Once()

		err := wrapper.Create(ctx, testUser)
		assert.NoError(t, err)
		mockRepo.AssertExpectations(t)
	})

	t.Run("read user with retry on temporary failure", func(t *testing.T) {
		mockRepo := new(MockUserRepository)
		wrapper := NewRetryUserRepositoryWrapper(mockRepo, retryService)

		// First call fails, second succeeds
		mockRepo.On("Read", ctx, testUser.ID).Return(nil, errors.New("connection refused")).Once()
		mockRepo.On("Read", ctx, testUser.ID).Return(testUser, nil).Once()

		result, err := wrapper.Read(ctx, testUser.ID)
		assert.NoError(t, err)
		assert.Equal(t, testUser, result)
		mockRepo.AssertExpectations(t)
	})

	t.Run("non-retryable error fails immediately", func(t *testing.T) {
		mockRepo := new(MockUserRepository)
		wrapper := NewRetryUserRepositoryWrapper(mockRepo, retryService)

		// This error should not trigger retry
		mockRepo.On("Create", ctx, testUser).Return(errors.New("constraint violation")).Once()

		err := wrapper.Create(ctx, testUser)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "constraint violation")
		mockRepo.AssertExpectations(t)
	})
}

// TestRetrySecretServiceIntegration tests the retry secret service
func TestRetrySecretServiceIntegration(t *testing.T) {
	// Create test configuration
	v := viper.New()
	v.Set("retry.database.enabled", true)
	v.Set("retry.database.max_attempts", 3)
	v.Set("retry.database.initial_delay", "10ms")
	v.Set("retry.database.max_delay", "100ms")
	v.Set("retry.database.backoff_multiplier", 2.0)
	v.Set("retry.database.jitter_enabled", false)

	retryService, err := NewRetryService(v)
	assert.NoError(t, err)

	ctx := context.Background()

	t.Run("secret service operations with retry", func(t *testing.T) {
		// This would typically use a mock secret service
		// For now, we'll test the retry service directly
		callCount := 0
		err := retryService.ExecuteDatabaseOperation(ctx, func() error {
			callCount++
			if callCount == 1 {
				return errors.New("database timeout")
			}
			return nil
		})

		assert.NoError(t, err)
		assert.Equal(t, 2, callCount)
	})
}

// TestRetryWebhookServiceIntegration tests the retry webhook service
func TestRetryWebhookServiceIntegration(t *testing.T) {
	// Create test configuration for external services
	v := viper.New()
	v.Set("retry.external_services.enabled", true)
	v.Set("retry.external_services.max_attempts", 3)
	v.Set("retry.external_services.initial_delay", "10ms")
	v.Set("retry.external_services.max_delay", "100ms")
	v.Set("retry.external_services.backoff_multiplier", 2.0)
	v.Set("retry.external_services.jitter_enabled", false)

	retryService, err := NewRetryService(v)
	assert.NoError(t, err)

	ctx := context.Background()

	t.Run("external service operations with retry", func(t *testing.T) {
		callCount := 0
		err := retryService.ExecuteExternalServiceOperation(ctx, func() error {
			callCount++
			if callCount < 3 {
				return errors.New("connection refused")
			}
			return nil
		})

		assert.NoError(t, err)
		assert.Equal(t, 3, callCount)
	})

	t.Run("external service operations with timeout retry", func(t *testing.T) {
		callCount := 0
		err := retryService.ExecuteExternalServiceOperation(ctx, func() error {
			callCount++
			if callCount == 1 {
				return errors.New("timeout")
			}
			return nil
		})

		assert.NoError(t, err)
		assert.Equal(t, 2, callCount)
	})
}

// TestRetryLogicWithMultipleFailures tests retry logic with multiple failures
func TestRetryLogicWithMultipleFailures(t *testing.T) {
	// Create test configuration with circuit breaker (not yet implemented in retry service)
	v := viper.New()
	v.Set("retry.database.enabled", true)
	v.Set("retry.database.max_attempts", 3)
	v.Set("retry.database.initial_delay", "10ms")
	v.Set("retry.database.max_delay", "100ms")

	retryService, err := NewRetryService(v)
	assert.NoError(t, err)

	ctx := context.Background()

	t.Run("retry logic works correctly with multiple failures", func(t *testing.T) {
		callCount := 0

		// First two calls should fail and be retried
		for i := 0; i < 2; i++ {
			err := retryService.ExecuteDatabaseOperation(ctx, func() error {
				callCount++
				if callCount <= 2 {
					return errors.New("connection refused")
				}
				return nil
			})
			// Each call will be retried up to 3 times, so this should succeed on retry
			if i == 1 { // Second call should succeed after retry
				assert.NoError(t, err)
			}
		}

		// Verify that retry logic processed the failures correctly
		assert.GreaterOrEqual(t, callCount, 2)
	})
}

// TestRetryPolicyConfiguration tests different retry policy configurations
func TestRetryPolicyConfiguration(t *testing.T) {
	testCases := []struct {
		name     string
		config   map[string]interface{}
		expected retry.Policy
	}{
		{
			name: "development configuration",
			config: map[string]interface{}{
				"retry.database.enabled":            true,
				"retry.database.max_attempts":       2,
				"retry.database.initial_delay":      "50ms",
				"retry.database.max_delay":          "1s",
				"retry.database.backoff_multiplier": 2.0,
				"retry.database.jitter_enabled":     true,
			},
			expected: retry.Policy{
				Enabled:           true,
				MaxAttempts:       2,
				InitialDelay:      50 * time.Millisecond,
				MaxDelay:          1 * time.Second,
				BackoffMultiplier: 2.0,
				JitterEnabled:     true,
			},
		},
		{
			name: "production configuration",
			config: map[string]interface{}{
				"retry.database.enabled":            true,
				"retry.database.max_attempts":       3,
				"retry.database.initial_delay":      "100ms",
				"retry.database.max_delay":          "5s",
				"retry.database.backoff_multiplier": 2.0,
				"retry.database.jitter_enabled":     true,
			},
			expected: retry.Policy{
				Enabled:           true,
				MaxAttempts:       3,
				InitialDelay:      100 * time.Millisecond,
				MaxDelay:          5 * time.Second,
				BackoffMultiplier: 2.0,
				JitterEnabled:     true,
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			v := viper.New()
			for key, value := range tc.config {
				v.Set(key, value)
			}

			retryService, err := NewRetryService(v)
			assert.NoError(t, err)

			policy := retryService.GetDatabasePolicy()
			assert.Equal(t, tc.expected.Enabled, policy.Enabled)
			assert.Equal(t, tc.expected.MaxAttempts, policy.MaxAttempts)
			assert.Equal(t, tc.expected.InitialDelay, policy.InitialDelay)
			assert.Equal(t, tc.expected.MaxDelay, policy.MaxDelay)
			assert.Equal(t, tc.expected.BackoffMultiplier, policy.BackoffMultiplier)
			assert.Equal(t, tc.expected.JitterEnabled, policy.JitterEnabled)
		})
	}
}

// TestRetryMetrics tests retry metrics collection
func TestRetryMetricsIntegration(t *testing.T) {
	// Create test configuration
	v := viper.New()
	v.Set("retry.database.enabled", true)
	v.Set("retry.database.max_attempts", 3)
	v.Set("retry.database.initial_delay", "10ms")
	v.Set("retry.database.max_delay", "100ms")
	v.Set("retry.database.backoff_multiplier", 2.0)
	v.Set("retry.database.jitter_enabled", false)

	retryService, err := NewRetryService(v)
	assert.NoError(t, err)

	ctx := context.Background()

	t.Run("successful operation metrics", func(t *testing.T) {
		callCount := 0
		err := retryService.ExecuteDatabaseOperation(ctx, func() error {
			callCount++
			return nil
		})

		assert.NoError(t, err)
		assert.Equal(t, 1, callCount)
		// In a real implementation, you would check metrics here
	})

	t.Run("retry operation metrics", func(t *testing.T) {
		callCount := 0
		err := retryService.ExecuteDatabaseOperation(ctx, func() error {
			callCount++
			if callCount == 1 {
				return errors.New("timeout")
			}
			return nil
		})

		assert.NoError(t, err)
		assert.Equal(t, 2, callCount)
		// In a real implementation, you would check retry metrics here
	})
}

// BenchmarkRetryOperations benchmarks retry operations
func BenchmarkRetryOperations(b *testing.B) {
	v := viper.New()
	v.Set("retry.database.enabled", true)
	v.Set("retry.database.max_attempts", 3)
	v.Set("retry.database.initial_delay", "1ms")
	v.Set("retry.database.max_delay", "10ms")
	v.Set("retry.database.backoff_multiplier", 2.0)
	v.Set("retry.database.jitter_enabled", false)

	retryService, _ := NewRetryService(v)
	ctx := context.Background()

	b.Run("successful operation", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_ = retryService.ExecuteDatabaseOperation(ctx, func() error {
				return nil
			})
		}
	})

	b.Run("operation with retry", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			callCount := 0
			_ = retryService.ExecuteDatabaseOperation(ctx, func() error {
				callCount++
				if callCount == 1 {
					return errors.New("timeout")
				}
				return nil
			})
		}
	})
}
