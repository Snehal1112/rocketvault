// Package api — audit attribution tests for vault handlers (B81).
package api

import (
	"net/http"
	"testing"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"rocketvault/app"
	"rocketvault/internal/logging"
	"rocketvault/internal/logging/logtest"
	vaultServices "rocketvault/internal/services/vaults"
	"rocketvault/model"
)

// newVaultAuditTestAPI builds a vault API around a real vault service that
// writes its audit rows to the given logger.
func newVaultAuditTestAPI(repo *vaultFakeRepo, logger *logging.Logger) *API {
	svc := vaultServices.NewVaultService(repo, vaultNoopCascade{}, logger)
	a := &app.App{ServiceContainer: &vaultSvcTestContainer{vaultSvc: svc, policySvc: &mockAccessPolicyService{}}}
	a.Logger = userTestLog()

	router := mux.NewRouter()
	api := &API{
		App:        a,
		BaseRoutes: &Routes{},
		basePath:   "/api/v1",
		rootRouter: router,
		Logger:     userTestLog(),
	}
	api.BaseRoutes.ApiRoot = router.PathPrefix("/api/v1").Subrouter()
	api.BaseRoutes.Vaults = api.BaseRoutes.ApiRoot.PathPrefix("/vaults").Subrouter()
	api.BaseRoutes.VaultScoped = api.BaseRoutes.Vaults.PathPrefix("/{vault_name:[a-z0-9-]+}").Subrouter()
	api.InitVault()
	return api
}

// TestDeleteVault_AuditsCallerAsActor proves the HTTP delete passes the
// session principal to the service, which records it.
func TestDeleteVault_AuditsCallerAsActor(t *testing.T) {
	logger, rec := logtest.NewLogger()
	repo := newVaultFakeRepo()
	id := uuid.New()
	repo.byName["stg"] = &model.Vault{ID: id, Name: "stg", Enabled: true}
	repo.byID[id.String()] = repo.byName["stg"]
	api := newVaultAuditTestAPI(repo, logger)

	w := doVaultRequest(api, http.MethodDelete, "/api/v1/vaults/stg", nil)
	require.Equal(t, http.StatusNoContent, w.Code)

	row, ok := rec.Find("delete_vault", "success")
	require.True(t, ok)
	assert.Equal(t, vaultTestUserID, row.UserID)
}

// TestPurgeVault_AuditsCallerAsActor mirrors the delete case for purge.
func TestPurgeVault_AuditsCallerAsActor(t *testing.T) {
	logger, rec := logtest.NewLogger()
	repo := newVaultFakeRepo()
	id := uuid.New()
	deletedAt := nowForVaultTest()
	repo.byName["stg"] = &model.Vault{ID: id, Name: "stg", Enabled: true, DeletedAt: &deletedAt}
	repo.byID[id.String()] = repo.byName["stg"]
	api := newVaultAuditTestAPI(repo, logger)

	w := doVaultRequest(api, http.MethodDelete, "/api/v1/vaults/stg/purge", nil)
	require.Equal(t, http.StatusNoContent, w.Code)

	row, ok := rec.Find("purge_vault", "success")
	require.True(t, ok)
	assert.Equal(t, vaultTestUserID, row.UserID)
}
