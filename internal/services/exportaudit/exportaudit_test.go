package exportaudit_test

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	auditServices "rocketvault/internal/services/audit"
	certServices "rocketvault/internal/services/certificates"
	"rocketvault/internal/services/exportaudit"
	keyServices "rocketvault/internal/services/keys"
	"rocketvault/model"
)

func TestClassify_MapsEveryServiceErrorToAFixedReason(t *testing.T) {
	cases := []struct {
		name     string
		err      error
		resource string
		kind     exportaudit.Kind
		code     string
		message  string
		reason   string
	}{
		{"certificate refusal", &model.ExportRefusedError{Sentinel: model.ErrCertificateNotExportable, Reason: "flag is false", Name: "client", KeyAlgorithm: "RSA-2048"},
			"certificate", exportaudit.KindNotExportable, "certificate_not_exportable", "certificate is not exportable: flag is false", "flag is false"},
		{"key refusal", &model.ExportRefusedError{Sentinel: model.ErrKeyNotExportable, Reason: "HSM-backed keys never leave the token"},
			"key", exportaudit.KindNotExportable, "key_not_exportable", "key is not exportable: HSM-backed keys never leave the token", "HSM-backed keys never leave the token"},
		{"invalid request", fmt.Errorf("%w: format must be pem or pkcs12", model.ErrInvalidExportRequest),
			"certificate", exportaudit.KindBadRequest, "bad_request", "invalid export request: format must be pem or pkcs12", "invalid export request"},
		{"certificate not found", fmt.Errorf("%w: sql: raw-detail", certServices.ErrCertNotFound),
			"certificate", exportaudit.KindNotFound, "not_found", "certificate or version not found", "certificate or version not found"},
		{"certificate version not found", fmt.Errorf("%w: raw-detail", model.ErrCertificateVersionNotFound),
			"certificate", exportaudit.KindNotFound, "not_found", "certificate or version not found", "certificate or version not found"},
		{"key not found", fmt.Errorf("%w: raw-detail", keyServices.ErrKeyNotFound),
			"key", exportaudit.KindNotFound, "not_found", "key or version not found", "key or version not found"},
		{"key version not found", fmt.Errorf("%w: raw-detail", model.ErrKeyVersionNotFound),
			"key", exportaudit.KindNotFound, "not_found", "key or version not found", "key or version not found"},
		{"certificate disabled", certServices.ErrCertLifecycleDenied,
			"certificate", exportaudit.KindDisabled, "certificate_disabled", "the certificate or this version is disabled or outside its valid time window", "certificate or version disabled"},
		{"key disabled", fmt.Errorf("%w", keyServices.ErrKeyLifecycleDenied),
			"key", exportaudit.KindDisabled, "key_disabled", "the key is disabled or outside its valid time window", "key disabled"},
		{"chain unavailable", fmt.Errorf("%w: issuer raw-detail", certServices.ErrCertificateChainUnavailable),
			"certificate", exportaudit.KindInternal, "internal_error", "internal server error", "certificate chain unavailable"},
		{"versioning unavailable", certServices.ErrCertVersioningUnavailable,
			"certificate", exportaudit.KindInternal, "internal_error", "internal server error", "certificate versioning unavailable"},
		{"unknown", errors.New("decrypt certificate key: raw-detail"),
			"certificate", exportaudit.KindInternal, "internal_error", "internal server error", "internal failure"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := exportaudit.Classify(c.err, c.resource)
			assert.Equal(t, c.kind, f.Kind)
			assert.Equal(t, c.code, f.Code)
			assert.Equal(t, c.message, f.Message)
			assert.Equal(t, c.reason, f.Reason)
			assert.NotContains(t, f.Message+f.Reason, "raw-detail")
		})
	}

	refusal := exportaudit.Classify(cases[0].err, "certificate")
	assert.Equal(t, "client", refusal.Name)
	assert.Equal(t, "RSA-2048", refusal.KeyAlgorithm)
}

func TestConstructors(t *testing.T) {
	assert.Equal(t, exportaudit.Failure{Kind: exportaudit.KindBadRequest, Code: "bad_request", Message: "m", Reason: "m"}, exportaudit.BadRequest("m"))
	assert.Equal(t, exportaudit.Failure{Kind: exportaudit.KindInternal, Code: "internal_error", Message: "internal server error", Reason: "r"}, exportaudit.Internal("r"))
	assert.Equal(t, exportaudit.Failure{Kind: exportaudit.KindForbidden, Code: "forbidden", Message: "r", Reason: "r"}, exportaudit.Forbidden("r"))
}

func TestAuditableFormat(t *testing.T) {
	assert.Equal(t, "pem", exportaudit.AuditableFormat("pem"))
	assert.Equal(t, "pkcs12", exportaudit.AuditableFormat("pkcs12"))
	for _, raw := range []string{"", "PEM", "der", "hunter2"} {
		assert.Equal(t, "invalid", exportaudit.AuditableFormat(raw), raw)
	}
}

func TestEvent_CarriesOnlyFixedFields(t *testing.T) {
	ev := exportaudit.Event(exportaudit.Attempt{
		UserID: "u1", ResourceType: "certificate", ResourceID: "c1", VaultID: "v1", Name: "client", Version: 2,
		Format: "pem", Outcome: "failure", Code: "certificate_not_exportable", Reason: "flag is false",
		IPAddress: "10.0.0.1", Source: "cli",
	})
	assert.Equal(t, auditServices.AuditEvent{
		UserID:       "u1",
		Action:       "export_certificate",
		Details:      `{"code":"certificate_not_exportable","format":"pem","name":"client","reason":"flag is false","vault_id":"v1","version":2}`,
		ResourceType: "certificate",
		ResourceID:   "c1",
		IPAddress:    "10.0.0.1",
		Outcome:      "failure",
		Source:       "cli",
	}, ev)
}

// recorder captures audit events.
type recorder struct{ events []auditServices.AuditEvent }

func (r *recorder) RecordEvent(_ context.Context, e auditServices.AuditEvent) error {
	r.events = append(r.events, e)
	return nil
}

func (r *recorder) PersistAudit(string, string, string) error { return nil }

func TestRecord_WritesOneEventAndToleratesANilService(t *testing.T) {
	exportaudit.Record(context.Background(), nil, exportaudit.Attempt{ResourceType: "key"})

	rec := &recorder{}
	exportaudit.Record(context.Background(), rec, exportaudit.Attempt{ResourceType: "key", Outcome: "success", Source: "cli"})
	require.Len(t, rec.events, 1)
	assert.Equal(t, "export_key", rec.events[0].Action)
	assert.Equal(t, "success", rec.events[0].Outcome)
}
