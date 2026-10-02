package auth

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const stepTestSecret = "JBSWY3DPEHPK3PXP"

// stepTestNow is a fixed instant so every test is deterministic.
var stepTestNow = time.Unix(1_700_000_000, 0)

func TestTOTPService_ValidateCodeWithStep_ReturnsMatchedStep(t *testing.T) {
	t.Parallel()
	svc := NewTOTPService()

	for _, offset := range []time.Duration{-60 * time.Second, -30 * time.Second, 0, 30 * time.Second, 60 * time.Second} {
		at := stepTestNow.Add(offset)
		code, err := svc.GenerateCode(stepTestSecret, at)
		require.NoError(t, err)

		step, valid, err := svc.ValidateCodeWithStep(code, stepTestSecret, stepTestNow)
		require.NoError(t, err)
		assert.True(t, valid, "offset %s must be inside the window", offset)
		assert.Equal(t, at.Unix()/30, step, "offset %s must return its own step", offset)
	}
}

func TestTOTPService_ValidateCodeWithStep_OutsideWindow(t *testing.T) {
	t.Parallel()
	svc := NewTOTPService()

	for _, offset := range []time.Duration{-90 * time.Second, 90 * time.Second} {
		code, err := svc.GenerateCode(stepTestSecret, stepTestNow.Add(offset))
		require.NoError(t, err)

		step, valid, err := svc.ValidateCodeWithStep(code, stepTestSecret, stepTestNow)
		require.NoError(t, err)
		assert.False(t, valid, "offset %s must be outside the window", offset)
		assert.Zero(t, step)
	}
}

func TestTOTPService_ValidateCodeWithStep_WrongCode(t *testing.T) {
	t.Parallel()
	svc := NewTOTPService()

	code, err := svc.GenerateCode(stepTestSecret, stepTestNow)
	require.NoError(t, err)

	// Flip the last digit so the code is the right length but wrong.
	last := (code[len(code)-1]-'0'+1)%10 + '0'
	wrong := code[:len(code)-1] + string(last)

	// The wrong code must not match any step in the window either.
	for offset := -60 * time.Second; offset <= 60*time.Second; offset += 30 * time.Second {
		other, genErr := svc.GenerateCode(stepTestSecret, stepTestNow.Add(offset))
		require.NoError(t, genErr)
		require.NotEqual(t, wrong, other, "test fixture collides with a window code")
	}

	step, valid, err := svc.ValidateCodeWithStep(wrong, stepTestSecret, stepTestNow)
	require.NoError(t, err)
	assert.False(t, valid)
	assert.Zero(t, step)
}

func TestTOTPService_ValidateCodeWithStep_TrimsWhitespace(t *testing.T) {
	t.Parallel()
	svc := NewTOTPService()

	code, err := svc.GenerateCode(stepTestSecret, stepTestNow)
	require.NoError(t, err)

	step, valid, err := svc.ValidateCodeWithStep(" "+code+"\n", stepTestSecret, stepTestNow)
	require.NoError(t, err)
	assert.True(t, valid)
	assert.Equal(t, stepTestNow.Unix()/30, step)
}

func TestTOTPService_ValidateCodeWithStep_EmptySecret(t *testing.T) {
	t.Parallel()
	svc := NewTOTPService()

	// An empty secret decodes to an empty HMAC key, which yields real codes.
	// This code is the one that empty key produces, so only the guard stops it.
	code, err := svc.GenerateCode("", stepTestNow)
	require.NoError(t, err)

	step, valid, err := svc.ValidateCodeWithStep(code, "", stepTestNow)
	require.Error(t, err)
	assert.False(t, valid)
	assert.Zero(t, step)
}

func TestTOTPService_ValidateCodeWithStep_WrongLength(t *testing.T) {
	t.Parallel()
	step, valid, err := NewTOTPService().ValidateCodeWithStep("12345", stepTestSecret, stepTestNow)
	require.NoError(t, err)
	assert.False(t, valid)
	assert.Zero(t, step)
}

func TestTOTPService_ValidateCodeWithStep_InvalidSecret(t *testing.T) {
	t.Parallel()
	step, valid, err := NewTOTPService().ValidateCodeWithStep("123456", "!!! not base32 !!!", stepTestNow)
	require.Error(t, err)
	assert.False(t, valid)
	assert.Zero(t, step)
}
