package certificates

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"rocketvault/model"
)

func TestCurrentValidityDays(t *testing.T) {
	now := time.Now()
	in90 := now.Add(90 * 24 * time.Hour)
	past := now.Add(-time.Hour)

	assert.Equal(t, 90, CurrentValidityDays(&model.Certificate{CreatedAt: now, ExpiresAt: &in90}))
	assert.Equal(t, 365, CurrentValidityDays(&model.Certificate{CreatedAt: now}), "no expiry falls back to 365")
	assert.Equal(t, 365, CurrentValidityDays(&model.Certificate{ExpiresAt: &in90}), "no creation time falls back to 365")
	assert.Equal(t, 365, CurrentValidityDays(&model.Certificate{CreatedAt: now, ExpiresAt: &past}), "a non-positive period falls back to 365")
	assert.Equal(t, 365, CurrentValidityDays(nil))
}
