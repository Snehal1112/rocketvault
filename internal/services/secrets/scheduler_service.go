// Package secrets provides business logic services for secret management operations.
// This package follows the established service layer patterns with dependency injection
// and proper separation of concerns.
package secrets

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"

	"rocketvault/internal/logging"
	"rocketvault/internal/pwgen"
	"rocketvault/internal/repositories"
	"rocketvault/internal/schedulerkit"
	"rocketvault/model"
)

// SchedulerServiceInterface defines the business logic contract for rotation scheduling.
// It orchestrates automated rotation and reminder operations with proper service coordination.
type SchedulerServiceInterface interface {
	// Scheduler lifecycle
	Start(ctx context.Context, interval time.Duration) error
	Stop() error
	IsRunning() bool

	// Manual operations
	ProcessUserRotations(ctx context.Context, userID uuid.UUID) error
	ProcessUserReminders(ctx context.Context, userID uuid.UUID) error
	PerformManualRotation(ctx context.Context, req ManualSchedulerRotationRequest) error
}

// ManualSchedulerRotationRequest represents a manual rotation request through
// the scheduler. Its value source is passed straight through to
// ManualRotationRequest, so the same "never invent a value" rule applies.
type ManualSchedulerRotationRequest struct {
	SecretID     uuid.UUID     `json:"secret_id" validate:"required"`
	PolicyID     uuid.UUID     `json:"policy_id" validate:"required"`
	UserID       uuid.UUID     `json:"user_id" validate:"required"`
	Notes        string        `json:"notes" validate:"max=500"`
	NewValue     string        `json:"new_value"`
	Generate     bool          `json:"generate"`
	GenerateOpts pwgen.Options `json:"generate_opts"`
}

// schedulerService implements SchedulerServiceInterface with service dependencies.
type schedulerService struct {
	rotationSvc   RotationServiceInterface
	versioningSvc VersioningServiceInterface
	userRepo      repositories.UserRepositoryInterface
	secretRepo    repositories.SecretRepositoryInterface
	rotationRepo  repositories.RotationPolicyRepositoryInterface
	log           *logging.Logger
	runner        *schedulerkit.Runner
}

// NewSchedulerService creates a new scheduler service with proper service dependencies.
func NewSchedulerService(
	rotationSvc RotationServiceInterface,
	versioningSvc VersioningServiceInterface,
	userRepo repositories.UserRepositoryInterface,
	secretRepo repositories.SecretRepositoryInterface,
	rotationRepo repositories.RotationPolicyRepositoryInterface,
	log *logging.Logger,
) SchedulerServiceInterface {
	s := &schedulerService{
		rotationSvc:   rotationSvc,
		versioningSvc: versioningSvc,
		userRepo:      userRepo,
		secretRepo:    secretRepo,
		rotationRepo:  rotationRepo,
		log:           log,
	}
	s.runner = schedulerkit.NewRunner("secret rotation", func(ctx context.Context) error {
		s.processAllUserOperations(ctx)
		return nil
	}, log)
	return s
}

// Start begins the rotation scheduler with business logic orchestration.
func (s *schedulerService) Start(ctx context.Context, interval time.Duration) error {
	return s.runner.Start(ctx, interval)
}

// Stop stops the rotation scheduler gracefully.
func (s *schedulerService) Stop() error {
	return s.runner.Stop()
}

// IsRunning returns whether the scheduler is currently running.
func (s *schedulerService) IsRunning() bool {
	return s.runner.IsRunning()
}

// processAllUserOperations processes rotations and reminders for all users.
func (s *schedulerService) processAllUserOperations(ctx context.Context) {
	// Get all users using proper repository pattern
	users, err := s.getAllUsers(ctx)
	if err != nil {
		s.log.WithError(err).Error("Failed to get users for rotation processing")
		return
	}

	for _, userID := range users {
		// Process rotations for this user
		err := s.ProcessUserRotations(ctx, userID)
		if err != nil {
			s.log.WithError(err).WithField("user_id", userID).Error("Failed to process user rotations")
		}

		// Process reminders for this user
		err = s.ProcessUserReminders(ctx, userID)
		if err != nil {
			s.log.WithError(err).WithField("user_id", userID).Error("Failed to process user reminders")
		}
	}
}

// ProcessUserRotations processes automatic rotations for a specific user.
//
// The scope is owner-scoped, not admin-scoped: model.NewOwnerScope's SQL
// predicate is "user_id = ?" bound to userID, which is exactly the
// "WHERE rp.user_id = ?" filter this query has always had. Its vaultID
// argument is advisory and never enters the predicate (see
// internal/repositories/scope_predicate.go), so uuid.Nil is correct here --
// this method is deliberately per-user, not per-vault. An admin scope would
// drop the predicate entirely and make every per-user pass process every
// user's work.
func (s *schedulerService) ProcessUserRotations(ctx context.Context, userID uuid.UUID) error {
	// Get due rotations using rotation service
	dueRotations, err := s.rotationSvc.GetDueRotations(ctx, model.NewOwnerScope(uuid.Nil, userID))
	if err != nil {
		return fmt.Errorf("failed to get due rotations for user %s: %w", userID, err)
	}

	for _, rotation := range dueRotations {
		err := s.performAutomaticRotation(ctx, rotation)
		if err != nil {
			s.log.WithError(err).WithFields(map[string]any{
				"user_id":   userID,
				"secret_id": rotation.SecretID,
				"policy_id": rotation.PolicyID,
			}).Error("Failed to perform automatic rotation")
		}
	}

	return nil
}

// ProcessUserReminders processes reminder notifications for a specific user.
// It is owner-scoped for the same reason ProcessUserRotations is: the scope
// reproduces this query's long-standing "WHERE rp.user_id = ?" filter.
func (s *schedulerService) ProcessUserReminders(ctx context.Context, userID uuid.UUID) error {
	// Get upcoming reminders using rotation service
	reminders, err := s.rotationSvc.GetUpcomingReminders(ctx, model.NewOwnerScope(uuid.Nil, userID))
	if err != nil {
		return fmt.Errorf("failed to get upcoming reminders for user %s: %w", userID, err)
	}

	for _, reminder := range reminders {
		err := s.sendReminder(ctx, reminder)
		if err != nil {
			s.log.WithError(err).WithFields(map[string]any{
				"user_id":     userID,
				"reminder_id": reminder.ID,
				"secret_id":   reminder.SecretID,
			}).Error("Failed to send reminder")
		}
	}

	return nil
}

// PerformManualRotation performs a manual rotation through the scheduler.
func (s *schedulerService) PerformManualRotation(ctx context.Context, req ManualSchedulerRotationRequest) error {
	// Delegate to rotation service
	rotationReq := ManualRotationRequest{
		SecretID:     req.SecretID,
		PolicyID:     req.PolicyID,
		Scope:        model.NewAdminScope(req.UserID),
		Notes:        req.Notes,
		NewValue:     req.NewValue,
		Generate:     req.Generate,
		GenerateOpts: req.GenerateOpts,
	}

	err := s.rotationSvc.PerformManualRotation(ctx, rotationReq)
	if err != nil {
		s.log.WithError(err).WithFields(map[string]any{
			"secret_id": req.SecretID,
			"policy_id": req.PolicyID,
			"user_id":   req.UserID,
		}).Error("Failed to perform manual rotation through scheduler")
		return fmt.Errorf("failed to perform manual rotation: %w", err)
	}

	s.log.WithFields(map[string]any{
		"secret_id": req.SecretID,
		"policy_id": req.PolicyID,
		"user_id":   req.UserID,
	}).Info("Manual rotation completed through scheduler")

	return nil
}

// performAutomaticRotation performs an automatic rotation for a secret-policy pair.
func (s *schedulerService) performAutomaticRotation(ctx context.Context, sp model.SecretPolicy) error {
	// Get the policy to check if auto-rotation is enabled
	policy, err := s.rotationSvc.GetPolicy(ctx, sp.PolicyID, model.NewAdminScope(uuid.Nil))
	if err != nil {
		return fmt.Errorf("failed to get policy: %w", err)
	}

	// Only auto-rotate if enabled
	if !policy.AutoRotate {
		s.log.WithFields(map[string]any{
			"secret_id": sp.SecretID,
			"policy_id": sp.PolicyID,
		}).Debug("Skipping automatic rotation - auto-rotate disabled")
		return nil
	}

	// Get the secret to determine user. Automatic rotation is a background
	// scheduler job with no per-request actor, so it reads with an admin
	// scope; the secret's own owner drives the version and rotation that follow.
	secret, err := s.secretRepo.Read(ctx, sp.SecretID, model.NewAdminScope(uuid.Nil))
	if err != nil {
		return fmt.Errorf("failed to get secret: %w", err)
	}

	// Perform automatic rotation using rotation service. Unattended rotation
	// has no operator to supply a value, so this is the one path where
	// generating one is the only option. Versioning is not repeated here:
	// PerformManualRotation archives the pre-rotation value itself, and a
	// second CreateVersion would write a duplicate row.
	rotationReq := ManualRotationRequest{
		SecretID:     sp.SecretID,
		PolicyID:     sp.PolicyID,
		Scope:        model.NewAdminScope(secret.UserID),
		Notes:        "Automatic rotation by scheduler",
		Generate:     true,
		GenerateOpts: pwgen.DefaultOptions(),
		Automatic:    true,
	}

	err = s.rotationSvc.PerformManualRotation(ctx, rotationReq)
	if err != nil {
		return fmt.Errorf("failed to perform automatic rotation: %w", err)
	}

	s.log.WithFields(map[string]any{
		"secret_id": sp.SecretID,
		"policy_id": sp.PolicyID,
		"user_id":   secret.UserID,
	}).Info("Automatic rotation completed")

	return nil
}

// sendReminder sends a reminder notification (placeholder implementation).
func (s *schedulerService) sendReminder(ctx context.Context, reminder model.RotationReminder) error {
	// In a real implementation, this would send email/SMS notifications
	// For now, we'll just log it and acknowledge the reminder
	s.log.WithFields(map[string]any{
		"reminder_id":   reminder.ID,
		"secret_id":     reminder.SecretID,
		"reminder_type": reminder.ReminderType,
		"sent_at":       reminder.SentAt,
	}).Info("Rotation reminder sent")

	// Acknowledge the reminder through rotation service. model.NewAdminScope
	// marks the scheduler as a trusted system caller with no access
	// predicate -- it is acknowledging its own generated reminder, not
	// acting on behalf of a specific user.
	err := s.rotationSvc.AcknowledgeReminder(ctx, reminder.ID, reminder.SecretID, model.NewAdminScope(uuid.Nil))
	if err != nil {
		return fmt.Errorf("failed to acknowledge reminder: %w", err)
	}

	return nil
}

// getAllUsers gets all user IDs using proper repository pattern.
func (s *schedulerService) getAllUsers(ctx context.Context) ([]uuid.UUID, error) {
	// Get all users using the existing List method from UserRepository
	users, err := s.userRepo.List(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to list users: %w", err)
	}

	// Extract user IDs from the user objects
	userIDs := make([]uuid.UUID, 0, len(users))
	for _, user := range users {
		userIDs = append(userIDs, user.ID)
	}

	return userIDs, nil
}
