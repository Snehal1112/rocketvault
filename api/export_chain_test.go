package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"rocketvault/app"
	"rocketvault/cmd/testutils"
	auditServices "rocketvault/internal/services/audit"
	authServices "rocketvault/internal/services/auth"
	certServices "rocketvault/internal/services/certificates"
	keyservices "rocketvault/internal/services/keys"
	"rocketvault/model"
)

// exportChainContainer is the cmd/testutils mock container with real
// certificate, key and audit services swapped in. Everything else keeps the
// stubs NewTestContext registers.
type exportChainContainer struct {
	*testutils.MockServiceContainer
	certSvc certServices.CertificateService
	keySvc  keyservices.KeyService
	audit   *captureAudit
}

func (c *exportChainContainer) GetCertificateService() certServices.CertificateService {
	return c.certSvc
}
func (c *exportChainContainer) GetKeyService() keyservices.KeyService { return c.keySvc }
func (c *exportChainContainer) GetAuditService() auditServices.AuditServiceInterface {
	return c.audit
}

// newExportChain serves the real router with the full production middleware
// chain. Every log line, from the app logger and the global logrus logger,
// lands in the returned buffer; every audit write lands in the capture.
// deny, when set, makes the role-assignment check refuse that action.
func newExportChain(t *testing.T, certSvc certServices.CertificateService, keySvc keyservices.KeyService, deny model.DataAction) (*mux.Router, *captureAudit, *bytes.Buffer) {
	t.Helper()
	for _, key := range []string{"rate_limit.default", "rate_limit.auth", "rate_limit.per_vault"} {
		previous := viper.Get(key)
		viper.Set(key, 1_000_000)
		t.Cleanup(func() { viper.Set(key, previous) })
	}

	tc := testutils.NewTestContext(t)
	logs := &bytes.Buffer{}
	tc.Logger.Logger.SetOutput(logs)
	tc.Logger.Logger.SetLevel(logrus.DebugLevel)
	previousOut := logrus.StandardLogger().Out
	logrus.SetOutput(logs)
	t.Cleanup(func() { logrus.SetOutput(previousOut) })

	audit := &captureAudit{}
	tc.Logger.SetAuditPersister(audit)

	tc.MockAuthService.On("ValidateSession", mock.Anything, mock.Anything).
		Return(&authServices.JWTClaims{UserID: tc.TestUserID, Username: "exporter", Roles: []string{model.RoleUser}}, nil).Maybe()
	tc.MockVaultService.On("GetVault", mock.Anything, mock.Anything).
		Return(&model.Vault{ID: tc.TestVaultID, Name: "default", Enabled: true}, nil).Maybe()
	tc.MockRBACService.On("ValidateEndpointAccess", mock.Anything, mock.Anything, mock.Anything).Return(nil).Maybe()
	if deny != "" {
		tc.MockRoleAssignmentService.ExpectedCalls = nil
		tc.MockRoleAssignmentService.On("HasDataAction", mock.Anything, mock.Anything, mock.Anything, deny).Return(false, nil).Maybe()
		tc.MockRoleAssignmentService.On("HasDataAction", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(true, nil).Maybe()
	}

	container := &exportChainContainer{MockServiceContainer: tc.MockContainer, certSvc: certSvc, keySvc: keySvc, audit: audit}
	router := mux.NewRouter()
	Init(
		WithAPP(&app.App{ServiceContainer: container, Logger: tc.Logger}),
		WithRouter(router),
		WithBasePath("/api/v1"),
		WithLogger(tc.Logger),
		WithMetricsEnabled(false),
	)
	return router, audit, logs
}

func postExport(router *mux.Router, path, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer chain-test-token")
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	return w
}

// TestExportThroughRealChain_NoSecretsInLogsOrAudit pins Review Focus 2.
func TestExportThroughRealChain_NoSecretsInLogsOrAudit(t *testing.T) {
	password := "pkcs12-password-must-not-leak"
	keyText := "-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgleaked\n-----END PRIVATE KEY-----\n"
	pfx := []byte("pfx-bytes-must-not-leak")
	certID := uuid.New()

	svc := &mockCertService{}
	svc.On("ExportCertificate", mock.Anything, mock.Anything, certID, mock.MatchedBy(func(r certServices.ExportCertificateRequest) bool {
		return r.Password != nil && *r.Password == password
	})).Return(&certServices.ExportCertificateResult{ID: certID, Name: "client", Version: 1, Format: "pkcs12",
		PKCS12: pfx, PrivateKeyPEM: keyText, KeyAlgorithm: "EC-P256"}, nil)
	svc.On("ExportCertificate", mock.Anything, mock.Anything, certID, mock.Anything).
		Return(&certServices.ExportCertificateResult{ID: certID, Name: "client", Version: 1, Format: "pem",
			CertificatePEM: "-----BEGIN CERTIFICATE-----\nX\n-----END CERTIFICATE-----\n", PrivateKeyPEM: keyText, KeyAlgorithm: "EC-P256"}, nil)

	router, audit, logs := newExportChain(t, svc, nil, "")
	body, _ := json.Marshal(map[string]any{"format": "pkcs12", "password": password})
	w := postExport(router, "/api/v1/certificates/"+certID.String()+"/export", string(body))
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	w = postExport(router, "/api/v1/vaults/default/certificates/"+certID.String()+"/export", `{"format":"pem"}`)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())

	everything := logs.String() + audit.dump()
	for _, secret := range []string{password, "BEGIN PRIVATE KEY", "MIGHAgEAMBMG", "leaked", string(pfx)} {
		assert.NotContains(t, everything, secret)
	}
	assert.Contains(t, audit.dump(), "export_certificate", "the attempt was audited")

	// Here the real logger has a persister, so a legacy row would show up.
	exportEvents := 0
	for _, e := range audit.events {
		if e.Action == "export_certificate" {
			exportEvents++
		}
	}
	assert.Equal(t, 2, exportEvents, "one structured event per attempt")
	for _, row := range audit.persisted {
		fields := strings.SplitN(row, " ", 3)
		require.Len(t, fields, 3, row)
		assert.NotEqual(t, "export_certificate", fields[1], "no legacy audit row for the export")
	}
}

// TestExportThroughRealChain_MissingRoleIsAudited pins that a principal
// without the exporter role gets the middleware's 403 and leaves a
// persisted audit record naming the export action.
func TestExportThroughRealChain_MissingRoleIsAudited(t *testing.T) {
	svc := &mockCertService{}
	router, audit, _ := newExportChain(t, svc, nil, model.ActionCertificatesExportItem)
	w := postExport(router, "/api/v1/certificates/"+uuid.NewString()+"/export", `{"format":"pem"}`)
	require.Equal(t, http.StatusForbidden, w.Code)
	assert.Contains(t, w.Body.String(), "no role assignment grants this operation")
	assert.Contains(t, audit.dump(), string(model.ActionCertificatesExportItem))
	svc.AssertNotCalled(t, "ExportCertificate", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
}
