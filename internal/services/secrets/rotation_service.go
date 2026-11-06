// Package secrets provides business logic services for secret management operations.
// This package follows the established service layer patterns with dependency injection
// and proper separation of concerns.
package secrets

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"

	"rocketvault/internal/logging"
	"rocketvault/internal/pwgen"
	"rocketvault/internal/repositories"
	auditServices "rocketvault/internal/services/audit"
	"rocketvault/model"
)

// RotationServiceInterface defines the business logic contract for secret rotation operations.
// It orchestrates rotation policies, scheduling, and history tracking.
type RotationServiceInterface interface {
	// Policy management
	CreatePolicy(ctx context.Context, req CreatePolicyRequest) (*model.RotationPolicy, error)
	GetPolicy(ctx context.Context, id uuid.UUID, scope model.Scope) (*model.RotationPolicy, error)
	UpdatePolicy(ctx context.Context, req UpdatePolicyRequest) (*model.RotationPolicy, error)
	DeletePolicy(ctx context.Context, id uuid.UUID, scope model.Scope) error
	ListPolicies(ctx context.Context, scope model.Scope) ([]model.RotationPolicy, error)

	// Secret-policy assignment
	AssignPolicyToSecret(ctx context.Context, req AssignPolicyRequest) error
	RemovePolicyFromSecret(ctx context.Context, secretID, policyID uuid.UUID, scope model.Scope) error
	GetSecretPolicies(ctx context.Context, secretID uuid.UUID, scope model.Scope) ([]model.RotationPolicy, error)

	// Rotation operations
	PerformManualRotation(ctx context.Context, req ManualRotationRequest) error
	GetRotationHistory(ctx context.Context, secretID uuid.UUID, scope model.Scope) ([]model.RotationHistory, error)
	GetDueRotations(ctx context.Context, scope model.Scope) ([]model.SecretPolicy, error)

	// Reminder management
	CreateRotationReminder(ctx context.Context, req CreateReminderRequest) error
	GetUpcomingReminders(ctx context.Context, scope model.Scope) ([]model.RotationReminder, error)
	// AcknowledgeReminder marks a reminder as acknowledged. secretID
	// identifies the secret the reminder belongs to; scope authorizes the
	// read that proves it. A system/scheduler caller passes
	// model.NewAdminScope(actorID) explicitly -- there is no longer a
	// sentinel value that skips the check.
	AcknowledgeReminder(ctx context.Context, reminderID, secretID uuid.UUID, scope model.Scope) error

	// SetAuditService attaches the audit service that writes the critical
	// attempt row for PerformManualRotation.
	SetAuditService(a auditServices.AuditServiceInterface)
}

// CreatePolicyRequest represents the request to create a rotation policy.
type CreatePolicyRequest struct {
	Scope        model.Scope // Authorization scope; its actor id owns the policy and its resolved vault id targets it.
	Name         string      `json:"name" validate:"required,min=1,max=100"`
	Description  string      `json:"description" validate:"max=500"`
	IntervalDays int         `json:"interval_days" validate:"required,min=1,max=365"`
	Enabled      bool        `json:"enabled"`
	ReminderDays int         `json:"reminder_days" validate:"min=0,max=30"`
	AutoRotate   bool        `json:"auto_rotate"`
}

// UpdatePolicyRequest represents the request to update a rotation policy.
type UpdatePolicyRequest struct {
	ID           uuid.UUID   `json:"id" validate:"required"`
	Scope        model.Scope // Authorization scope for the read and the write.
	Name         string      `json:"name" validate:"required,min=1,max=100"`
	Description  string      `json:"description" validate:"max=500"`
	IntervalDays int         `json:"interval_days" validate:"required,min=1,max=365"`
	Enabled      bool        `json:"enabled"`
	ReminderDays int         `json:"reminder_days" validate:"min=0,max=30"`
	AutoRotate   bool        `json:"auto_rotate"`
}

// AssignPolicyRequest represents the request to assign a policy to a secret.
type AssignPolicyRequest struct {
	SecretID uuid.UUID   `json:"secret_id" validate:"required"`
	PolicyID uuid.UUID   `json:"policy_id" validate:"required"`
	Scope    model.Scope // Authorization scope shared by both the secret and the policy read.
}

// ManualRotationRequest represents the request to perform manual rotation.
//
// Exactly one value source must be set. Rotation never invents a value: with
// neither NewValue nor Generate it fails, because a generated string is wrong
// whenever the secret must match an external system, and silently keeping the
// old value would be a rotation that rotated nothing.
type ManualRotationRequest struct {
	SecretID uuid.UUID   `json:"secret_id" validate:"required"`
	PolicyID uuid.UUID   `json:"policy_id" validate:"required"`
	Scope    model.Scope // Authorization scope shared by both the secret and the policy read.
	Notes    string      `json:"notes" validate:"max=500"`
	// NewValue is the explicit replacement value, in plaintext.
	NewValue string `json:"new_value"`
	// Generate asks for a random replacement value instead of an explicit one.
	Generate bool `json:"generate"`
	// GenerateOpts tunes generation. A zero value means pwgen.DefaultOptions.
	GenerateOpts pwgen.Options `json:"generate_opts"`
}

// ErrRotationValueRequired is returned when a rotation request names no value
// source at all.
var ErrRotationValueRequired = errors.New("rotation requires a new value: set NewValue or Generate")

// ErrRotationValueConflict is returned when a rotation request names both
// value sources, which is ambiguous rather than a precedence question.
var ErrRotationValueConflict = errors.New("rotation cannot take both an explicit value and a generated one")

// CreateReminderRequest represents the request to create a rotation reminder.
type CreateReminderRequest struct {
	SecretID       uuid.UUID  `json:"secret_id" validate:"required"`
	PolicyID       uuid.UUID  `json:"policy_id" validate:"required"`
	ReminderType   string     `json:"reminder_type" validate:"required,oneof=upcoming overdue"`
	NextReminderAt *time.Time `json:"next_reminder_at"`
}

// rotationService implements RotationServiceInterface.
type rotationService struct {
	rotationRepo  repositories.RotationPolicyRepositoryInterface
	secretRepo    repositories.SecretRepositoryInterface
	userRepo      repositories.UserRepositoryInterface
	cryptoSvc     CryptographyService
	versioningSvc VersioningServiceInterface
	cacheInv      SecretCacheInvalidator
	log           *logging.Logger
	// audit writes the critical rotation row. Nil only in tests; the
	// container always wires it.
	audit auditServices.AuditServiceInterface
}

// NewRotationService creates a new rotation service with the required
// dependencies. cacheInv is needed because PerformManualRotation writes the
// secrets table without going through CachedSecretService. The container
// always constructs a real (possibly no-op-backed) invalidator; a nil
// cacheInv (e.g. from a test) is defaulted to a no-op implementation so
// invalidateCache never nil-derefs.
// versioningSvc archives the pre-rotation value: rotation must never overwrite
// a secret it has not first written to a version row.
func NewRotationService(
	rotationRepo repositories.RotationPolicyRepositoryInterface,
	secretRepo repositories.SecretRepositoryInterface,
	userRepo repositories.UserRepositoryInterface,
	cryptoSvc CryptographyService,
	versioningSvc VersioningServiceInterface,
	log *logging.Logger,
	cacheInv SecretCacheInvalidator,
) RotationServiceInterface {
	if cacheInv == nil {
		cacheInv = noopSecretCacheInvalidator{}
	}
	return &rotationService{
		rotationRepo:  rotationRepo,
		secretRepo:    secretRepo,
		userRepo:      userRepo,
		cryptoSvc:     cryptoSvc,
		versioningSvc: versioningSvc,
		cacheInv:      cacheInv,
		log:           log,
	}
}

// SetAuditService attaches the audit service for the critical rotation row.
// See rotationService.audit.
func (s *rotationService) SetAuditService(a auditServices.AuditServiceInterface) { s.audit = a }

// invalidateCache evicts every cached view of a secret after a direct write.
// A failure is logged but never fails the rotation that already succeeded.
func (s *rotationService) invalidateCache(ctx context.Context, secretID uuid.UUID) {
	if err := s.cacheInv.DeleteByID(ctx, secretID); err != nil {
		s.log.WithError(err).WithField("secret_id", secretID).Warn("Failed to invalidate cached secret")
	}
}

// CreatePolicy creates a new rotation policy with business validation.
func (s *rotationService) CreatePolicy(ctx context.Context, req CreatePolicyRequest) (*model.RotationPolicy, error) {
	// Validate the actor exists.
	actorID := req.Scope.ActorID()
	if _, err := s.userRepo.Read(ctx, actorID); err != nil {
		s.log.WithError(err).WithField("user_id", actorID).Error("User not found for policy creation")
		return nil, fmt.Errorf("user not found: %w", err)
	}

	// Business validation
	if req.ReminderDays >= req.IntervalDays {
		return nil, fmt.Errorf("reminder days (%d) must be less than interval days (%d)", req.ReminderDays, req.IntervalDays)
	}

	// Create policy domain object with generated ID and timestamps
	now := time.Now()
	policy := &model.RotationPolicy{
		ID:           uuid.New(),
		UserID:       actorID,
		VaultID:      req.Scope.ResolvedVaultID(),
		Name:         req.Name,
		Description:  req.Description,
		IntervalDays: req.IntervalDays,
		Enabled:      req.Enabled,
		ReminderDays: req.ReminderDays,
		AutoRotate:   req.AutoRotate,
		CreatedAt:    now,
		UpdatedAt:    now,
	}

	if err := s.rotationRepo.Create(ctx, policy); err != nil {
		s.log.WithError(err).Error("Failed to create rotation policy")
		return nil, fmt.Errorf("failed to create rotation policy: %w", err)
	}

	s.log.WithFields(map[string]interface{}{
		"policy_id": policy.ID,
		"user_id":   policy.UserID,
		"name":      policy.Name,
	}).Info("Rotation policy created successfully")

	return policy, nil
}

// GetPolicy retrieves a rotation policy by ID, authorized by scope.
func (s *rotationService) GetPolicy(ctx context.Context, id uuid.UUID, scope model.Scope) (*model.RotationPolicy, error) {
	policy, err := s.rotationRepo.Read(ctx, id, scope)
	if err != nil {
		s.log.WithError(err).WithField("policy_id", id).Error("Failed to get rotation policy")
		return nil, fmt.Errorf("failed to get rotation policy: %w", err)
	}
	return policy, nil
}

// UpdatePolicy updates an existing rotation policy with business validation.
func (s *rotationService) UpdatePolicy(ctx context.Context, req UpdatePolicyRequest) (*model.RotationPolicy, error) {
	existingPolicy, err := s.rotationRepo.Read(ctx, req.ID, req.Scope)
	if err != nil {
		return nil, fmt.Errorf("policy not found: %w", err)
	}

	// Business validation
	if req.ReminderDays >= req.IntervalDays {
		return nil, fmt.Errorf("reminder days (%d) must be less than interval days (%d)", req.ReminderDays, req.IntervalDays)
	}

	// Update policy with new values
	policy := &model.RotationPolicy{
		ID:           req.ID,
		UserID:       existingPolicy.UserID,
		VaultID:      existingPolicy.VaultID,
		Name:         req.Name,
		Description:  req.Description,
		IntervalDays: req.IntervalDays,
		Enabled:      req.Enabled,
		ReminderDays: req.ReminderDays,
		AutoRotate:   req.AutoRotate,
		CreatedAt:    existingPolicy.CreatedAt,
		UpdatedAt:    time.Now(),
	}

	if err := s.rotationRepo.Update(ctx, policy, req.Scope); err != nil {
		s.log.WithError(err).Error("Failed to update rotation policy")
		return nil, fmt.Errorf("failed to update rotation policy: %w", err)
	}

	s.log.WithFields(map[string]interface{}{
		"policy_id": policy.ID,
		"user_id":   policy.UserID,
		"name":      policy.Name,
	}).Info("Rotation policy updated successfully")

	return policy, nil
}

// DeletePolicy deletes a rotation policy, authorized by scope.
func (s *rotationService) DeletePolicy(ctx context.Context, id uuid.UUID, scope model.Scope) error {
	if err := s.rotationRepo.Delete(ctx, id, scope); err != nil {
		s.log.WithError(err).WithField("policy_id", id).Error("Failed to delete rotation policy")
		return fmt.Errorf("failed to delete rotation policy: %w", err)
	}

	s.log.WithFields(map[string]interface{}{
		"policy_id": id,
		"actor":     scope.ActorID(),
	}).Info("Rotation policy deleted successfully")

	return nil
}

// ListPolicies lists rotation policies authorized by scope.
func (s *rotationService) ListPolicies(ctx context.Context, scope model.Scope) ([]model.RotationPolicy, error) {
	policies, err := s.rotationRepo.List(ctx, scope)
	if err != nil {
		s.log.WithError(err).Error("Failed to list rotation policies")
		return nil, fmt.Errorf("failed to list rotation policies: %w", err)
	}
	return policies, nil
}

// AssignPolicyToSecret assigns a rotation policy to a secret. The secret and
// policy are both read under req.Scope: a secret or policy outside that
// scope's vault fails its own scoped read before any comparison would run,
// which makes a cross-vault assignment structurally impossible without a
// separate ErrPolicyVaultMismatch check.
func (s *rotationService) AssignPolicyToSecret(ctx context.Context, req AssignPolicyRequest) error {
	secret, err := s.secretRepo.Read(ctx, req.SecretID, req.Scope)
	if err != nil {
		return fmt.Errorf("secret not found: %w", err)
	}
	policy, err := s.rotationRepo.Read(ctx, req.PolicyID, req.Scope)
	if err != nil {
		return fmt.Errorf("policy not found: %w", err)
	}
	// secret and policy are both confirmed to be in req.Scope's vault by the
	// two reads above -- a cross-vault assignment is denied here without a
	// separate comparison, because either read alone would already have failed.
	_ = secret // fetched only to prove scope membership; no field of it is used further

	// Calculate rotation schedule
	now := time.Now()
	nextRotation := now.AddDate(0, 0, policy.IntervalDays)

	if err := s.rotationRepo.AssignToSecret(ctx, req.SecretID, req.PolicyID, now, nextRotation); err != nil {
		s.log.WithError(err).Error("Failed to assign policy to secret")
		return fmt.Errorf("failed to assign policy to secret: %w", err)
	}

	// Create initial reminder if reminder days configured
	if policy.ReminderDays > 0 {
		reminderTime := nextRotation.AddDate(0, 0, -policy.ReminderDays)
		reminderReq := CreateReminderRequest{
			SecretID:       req.SecretID,
			PolicyID:       req.PolicyID,
			ReminderType:   model.ReminderUpcoming,
			NextReminderAt: &reminderTime,
		}

		if err := s.CreateRotationReminder(ctx, reminderReq); err != nil {
			s.log.WithError(err).Warn("Failed to create initial reminder for policy assignment")
			// Don't fail the assignment if reminder creation fails
		}
	}

	s.log.WithFields(map[string]interface{}{
		"secret_id":     req.SecretID,
		"policy_id":     req.PolicyID,
		"actor":         req.Scope.ActorID(),
		"next_rotation": nextRotation,
	}).Info("Policy assigned to secret successfully")

	return nil
}

// RemovePolicyFromSecret removes a rotation policy from a secret. The secret
// is read under scope to prove it is reachable; the scoped read is the only
// gate, there is no separate ownership comparison.
func (s *rotationService) RemovePolicyFromSecret(ctx context.Context, secretID, policyID uuid.UUID, scope model.Scope) error {
	secret, err := s.secretRepo.Read(ctx, secretID, scope)
	if err != nil {
		return fmt.Errorf("secret not found: %w", err)
	}
	_ = secret // fetched only to prove scope membership; no field of it is used further

	if err := s.rotationRepo.RemoveFromSecret(ctx, secretID, policyID); err != nil {
		s.log.WithError(err).Error("Failed to remove policy from secret")
		return fmt.Errorf("failed to remove policy from secret: %w", err)
	}

	s.log.WithFields(map[string]interface{}{
		"secret_id": secretID,
		"policy_id": policyID,
		"actor":     scope.ActorID(),
	}).Info("Policy removed from secret successfully")

	return nil
}

// GetSecretPolicies gets all rotation policies assigned to a secret. The
// secret is read under scope to prove it is reachable; the scoped read is
// the only gate, there is no separate ownership comparison and no sentinel
// value that skips it -- a system/scheduler caller passes
// model.NewAdminScope explicitly.
func (s *rotationService) GetSecretPolicies(ctx context.Context, secretID uuid.UUID, scope model.Scope) ([]model.RotationPolicy, error) {
	secret, err := s.secretRepo.Read(ctx, secretID, scope)
	if err != nil {
		return nil, fmt.Errorf("secret not found: %w", err)
	}
	_ = secret // fetched only to prove scope membership; no field of it is used further

	policies, err := s.rotationRepo.GetPoliciesForSecret(ctx, secretID)
	if err != nil {
		s.log.WithError(err).WithField("secret_id", secretID).Error("Failed to get secret policies")
		return nil, fmt.Errorf("failed to get secret policies: %w", err)
	}

	return policies, nil
}

// PerformManualRotation performs manual rotation with full business logic.
//
// It writes the secrets table directly rather than through the secret service,
// so it owns both its audit trail and its cache invalidation. The secret and
// policy are both read under req.Scope, the same structural cross-vault
// guard AssignPolicyToSecret uses.
//
// The order is deliberate: resolve the replacement value, archive the value
// being replaced, encrypt, then write. Archiving is fatal on failure -- a
// rotation that cannot preserve the old value must not destroy it.
func (s *rotationService) PerformManualRotation(ctx context.Context, req ManualRotationRequest) error {
	actor := req.Scope.ActorID().String()

	newPlaintext, err := resolveRotationValue(req)
	if err != nil {
		s.log.LogAuditError(actor, "rotate_secret", "failed", "No usable replacement value in the request", err)
		return err
	}

	secret, err := s.secretRepo.Read(ctx, req.SecretID, req.Scope)
	if err != nil {
		s.log.LogAuditError(actor, "rotate_secret", "failed", "Secret not found", err)
		return fmt.Errorf("secret not found: %w", err)
	}

	policy, err := s.rotationRepo.Read(ctx, req.PolicyID, req.Scope)
	if err != nil {
		s.log.LogAuditError(actor, "rotate_secret", "failed", "Rotation policy not found", err)
		return fmt.Errorf("policy not found: %w", err)
	}

	// The attempt row must be written before the old value is archived or
	// replaced. A failed write returns audit.ErrAuditUnavailable and the
	// secret, its versions and its schedule stay as they were; the scheduler
	// retries a due secret on its next tick.
	previousVersion := secret.Version
	if err := s.runCritical(ctx, req, secret, func(ctx context.Context) error {
		return s.replaceSecretValue(ctx, actor, secret, newPlaintext)
	}); err != nil {
		return err
	}

	// The write bypassed CachedSecretService. Without this eviction a
	// credential rotated because it was compromised would keep being served
	// from cache for the full TTL after rotation reported success.
	s.invalidateCache(ctx, req.SecretID)

	// Record rotation history
	now := time.Now()
	history := &model.RotationHistory{
		ID:              uuid.New(),
		SecretID:        req.SecretID,
		PolicyID:        &req.PolicyID,
		RotatedAt:       now,
		PreviousVersion: previousVersion,
		NewVersion:      secret.Version,
		TriggeredBy:     model.TriggerManual,
		Notes:           req.Notes,
	}

	if err := s.rotationRepo.RecordRotation(ctx, history); err != nil {
		s.log.WithError(err).Error("Failed to record rotation history")
		// Don't fail rotation if history recording fails
	}

	// Update next rotation time
	nextRotation := now.AddDate(0, 0, policy.IntervalDays)
	if err := s.rotationRepo.UpdateSecretPolicyRotation(ctx, req.SecretID, req.PolicyID, now, nextRotation); err != nil {
		s.log.WithError(err).Error("Failed to update next rotation time")
		// Don't fail rotation if scheduling update fails
	}

	if s.audit == nil {
		s.log.LogAuditInfo(actor, "rotate_secret", "success",
			fmt.Sprintf("Secret %s rotated to version %d", req.SecretID, secret.Version))
	}

	s.log.WithFields(map[string]interface{}{
		"secret_id":   req.SecretID,
		"policy_id":   req.PolicyID,
		"actor":       actor,
		"new_version": secret.Version,
	}).Info("Manual rotation completed successfully")

	return nil
}

// runCritical runs op after a critical attempt row for rotating secret on
// behalf of req's actor, and records its result. With no audit service wired
// (tests only) it runs op directly.
func (s *rotationService) runCritical(ctx context.Context, req ManualRotationRequest, secret *model.Secret, op func(context.Context) error) error {
	if s.audit == nil {
		return op(ctx)
	}
	details, _ := json.Marshal(map[string]any{
		"vault_id": secret.VaultID.String(), "policy_id": req.PolicyID.String(), "version": secret.Version,
	})
	return auditServices.WithCritical(ctx, s.audit, auditServices.AuditEvent{
		UserID: req.Scope.ActorID().String(), Action: "rotate_secret", Details: string(details),
		ResourceType: "secret", ResourceID: secret.ID.String(), Source: "system",
	}, op)
}

// replaceSecretValue archives secret's current value as a version, then
// stores newPlaintext as its next version.
func (s *rotationService) replaceSecretValue(ctx context.Context, actor string, secret *model.Secret, newPlaintext string) error {
	// The stored value is ciphertext and CreateVersion encrypts whatever it is
	// given, so the plaintext is what must be archived -- exactly as
	// SecretService.UpdateSecret does. Passing the ciphertext straight through
	// would store it doubly encrypted.
	currentPlaintext, err := s.cryptoSvc.DecryptSecret(secret.Value)
	if err != nil {
		s.log.LogAuditError(actor, "rotate_secret", "failed", "Failed to decrypt the current value", err)
		return fmt.Errorf("failed to decrypt the current secret value: %w", err)
	}

	// CreateVersion gates on secret.UserID == req.UserID, so pass the secret's
	// real owner here, never the scope's actor: a legitimate vault-scoped
	// rotation by a non-owner member must not be rejected by that gate.
	if _, err = s.versioningSvc.CreateVersion(ctx, CreateVersionRequest{
		SecretID: secret.ID,
		UserID:   secret.UserID,
		Name:     secret.Name,
		Value:    currentPlaintext,
		Version:  secret.Version,
	}); err != nil {
		s.log.LogAuditError(actor, "rotate_secret", "failed", "Failed to archive the pre-rotation value", err)
		return fmt.Errorf("failed to archive the pre-rotation value: %w", err)
	}

	encryptedValue, err := s.cryptoSvc.EncryptSecret(newPlaintext)
	if err != nil {
		s.log.LogAuditError(actor, "rotate_secret", "failed", "Failed to encrypt the replacement value", err)
		return fmt.Errorf("failed to encrypt the replacement value: %w", err)
	}

	// Update secret with new value and incremented version
	secret.Value = encryptedValue
	secret.Version++

	if err := s.secretRepo.Update(ctx, secret, model.NewOwnerScope(secret.VaultID, secret.UserID)); err != nil {
		s.log.WithError(err).Error("Failed to update secret during rotation")
		s.log.LogAuditError(actor, "rotate_secret", "failed", "Failed to update secret during rotation", err)
		return fmt.Errorf("failed to update secret during rotation: %w", err)
	}
	return nil
}

// GetRotationHistory retrieves rotation history for a secret. The secret is
// read under scope to prove it is reachable; the underlying history query
// itself has no scope parameter, so the scoped secret read is the gate.
func (s *rotationService) GetRotationHistory(ctx context.Context, secretID uuid.UUID, scope model.Scope) ([]model.RotationHistory, error) {
	secret, err := s.secretRepo.Read(ctx, secretID, scope)
	if err != nil {
		return nil, fmt.Errorf("secret not found: %w", err)
	}
	_ = secret // fetched only to prove scope membership; no field of it is used further

	history, err := s.rotationRepo.GetRotationHistory(ctx, secretID)
	if err != nil {
		s.log.WithError(err).WithField("secret_id", secretID).Error("Failed to get rotation history")
		return nil, fmt.Errorf("failed to get rotation history: %w", err)
	}

	return history, nil
}

// GetDueRotations gets secrets that are due for rotation, authorized by scope.
func (s *rotationService) GetDueRotations(ctx context.Context, scope model.Scope) ([]model.SecretPolicy, error) {
	due, err := s.rotationRepo.GetDueRotations(ctx, scope)
	if err != nil {
		s.log.WithError(err).WithField("actor", scope.ActorID()).Error("Failed to get due rotations")
		return nil, fmt.Errorf("failed to get due rotations: %w", err)
	}

	return due, nil
}

// CreateRotationReminder creates a rotation reminder.
func (s *rotationService) CreateRotationReminder(ctx context.Context, req CreateReminderRequest) error {
	// Validate reminder type
	if req.ReminderType != model.ReminderUpcoming && req.ReminderType != model.ReminderOverdue {
		return fmt.Errorf("invalid reminder type: %s", req.ReminderType)
	}

	now := time.Now()
	reminder := &model.RotationReminder{
		ID:             uuid.New(),
		SecretID:       req.SecretID,
		PolicyID:       req.PolicyID,
		ReminderType:   req.ReminderType,
		SentAt:         now,
		NextReminderAt: req.NextReminderAt,
		Acknowledged:   false,
	}

	if err := s.rotationRepo.CreateReminder(ctx, reminder); err != nil {
		s.log.WithError(err).Error("Failed to create rotation reminder")
		return fmt.Errorf("failed to create rotation reminder: %w", err)
	}

	s.log.WithFields(map[string]interface{}{
		"reminder_id": reminder.ID,
		"secret_id":   req.SecretID,
		"type":        req.ReminderType,
	}).Info("Rotation reminder created successfully")

	return nil
}

// GetUpcomingReminders gets upcoming rotation reminders, authorized by scope.
func (s *rotationService) GetUpcomingReminders(ctx context.Context, scope model.Scope) ([]model.RotationReminder, error) {
	reminders, err := s.rotationRepo.GetUpcomingReminders(ctx, scope)
	if err != nil {
		s.log.WithError(err).WithField("actor", scope.ActorID()).Error("Failed to get upcoming reminders")
		return nil, fmt.Errorf("failed to get upcoming reminders: %w", err)
	}

	return reminders, nil
}

// AcknowledgeReminder marks a reminder as acknowledged. secretID identifies
// the secret the reminder belongs to; scope authorizes the read that proves
// it is reachable. There is no longer a sentinel value that skips the check
// -- a system/scheduler caller passes model.NewAdminScope explicitly.
func (s *rotationService) AcknowledgeReminder(ctx context.Context, reminderID, secretID uuid.UUID, scope model.Scope) error {
	secret, err := s.secretRepo.Read(ctx, secretID, scope)
	if err != nil {
		return fmt.Errorf("secret not found: %w", err)
	}
	_ = secret // fetched only to prove scope membership; no field of it is used further

	// This would typically fetch the reminder first, then update it.
	// For simplicity, we'll create a reminder object with just the ID and
	// acknowledged status.
	reminder := &model.RotationReminder{
		ID:           reminderID,
		Acknowledged: true,
	}

	if err := s.rotationRepo.UpdateReminder(ctx, reminder); err != nil {
		s.log.WithError(err).WithField("reminder_id", reminderID).Error("Failed to acknowledge reminder")
		return fmt.Errorf("failed to acknowledge reminder: %w", err)
	}

	s.log.WithField("reminder_id", reminderID).Info("Reminder acknowledged successfully")
	return nil
}

// resolveRotationValue returns the plaintext a rotation should write. It is a
// pure function of the request, so it runs before any I/O and a bad request
// costs nothing.
func resolveRotationValue(req ManualRotationRequest) (string, error) {
	switch {
	case req.NewValue != "" && req.Generate:
		return "", ErrRotationValueConflict
	case req.NewValue != "":
		return req.NewValue, nil
	case req.Generate:
		opts := req.GenerateOpts
		if opts == (pwgen.Options{}) {
			opts = pwgen.DefaultOptions()
		}
		value, err := pwgen.Generate(opts)
		if err != nil {
			return "", fmt.Errorf("failed to generate a replacement value: %w", err)
		}
		return value, nil
	default:
		return "", ErrRotationValueRequired
	}
}
