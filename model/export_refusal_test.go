package model_test

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"

	"rocketvault/model"
)

func TestExportRefusedError_UnwrapsToItsSentinel(t *testing.T) {
	var err error = &model.ExportRefusedError{Sentinel: model.ErrCertificateNotExportable, Reason: "flag is false", KeyAlgorithm: "RSA-2048"}
	assert.True(t, errors.Is(err, model.ErrCertificateNotExportable))
	assert.False(t, errors.Is(err, model.ErrKeyNotExportable))
	assert.Equal(t, "certificate is not exportable: flag is false", err.Error())

	var refusal *model.ExportRefusedError
	assert.True(t, errors.As(err, &refusal))
	assert.Equal(t, "RSA-2048", refusal.KeyAlgorithm)
}
