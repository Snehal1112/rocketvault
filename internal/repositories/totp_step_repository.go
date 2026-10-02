package repositories

import (
	"context"
	"fmt"

	"github.com/google/uuid"

	"rocketvault/internal/db"
)

// TOTPStepRepositoryInterface records the last TOTP time step each user has used.
type TOTPStepRepositoryInterface interface {
	// ClaimTOTPStep stores step as the user's last accepted TOTP time step.
	// It returns false when step is not newer than the stored one.
	ClaimTOTPStep(ctx context.Context, userID uuid.UUID, step int64) (bool, error)
}

// TOTPStepRepository implements TOTPStepRepositoryInterface on users.totp_last_step.
type TOTPStepRepository struct {
	db db.DB
}

// NewTOTPStepRepository creates a TOTPStepRepository.
func NewTOTPStepRepository(conn db.DB) TOTPStepRepositoryInterface {
	return &TOTPStepRepository{db: conn}
}

// ClaimTOTPStep is one conditional UPDATE, so two logins racing with the same
// code cannot both see the step as unused.
func (r *TOTPStepRepository) ClaimTOTPStep(ctx context.Context, userID uuid.UUID, step int64) (bool, error) {
	var claimed bool
	err := withMetrics("users", "claim_totp_step", func() error {
		result, err := r.db.ExecContext(ctx,
			"UPDATE users SET totp_last_step = ? WHERE id = ? AND totp_last_step < ?",
			step, userID.String(), step)
		if err != nil {
			return fmt.Errorf("failed to claim TOTP step: %w", err)
		}
		rowsAffected, err := result.RowsAffected()
		if err != nil {
			return fmt.Errorf("failed to get rows affected: %w", err)
		}
		claimed = rowsAffected == 1
		return nil
	})
	return claimed, err
}
