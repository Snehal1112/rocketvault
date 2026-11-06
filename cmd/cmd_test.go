package cmd

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"rocketvault/cmd/testutils"
	"rocketvault/common"
	"rocketvault/internal/health"
	"rocketvault/internal/logging"
	secretServices "rocketvault/internal/services/secrets"
	"rocketvault/model"
)

// ---------------------------------------------------------------------------
// getEnv
// ---------------------------------------------------------------------------

func TestGetEnv_EnvSet(t *testing.T) {
	const key = "TEST_GETENV_CMD_ABC"
	t.Setenv(key, "hello")
	got := getEnv(key, "default")
	if got != "hello" {
		t.Errorf("getEnv = %q, want hello", got)
	}
}

func TestGetEnv_EnvNotSet(t *testing.T) {
	const key = "TEST_GETENV_CMD_NOTSET_XYZ"
	os.Unsetenv(key) //nolint:errcheck
	got := getEnv(key, "fallback")
	if got != "fallback" {
		t.Errorf("getEnv = %q, want fallback", got)
	}
}

func TestGetEnv_EmptyEnvValue(t *testing.T) {
	const key = "TEST_GETENV_CMD_EMPTY"
	t.Setenv(key, "")
	got := getEnv(key, "default_val")
	// Empty value should fall back to default.
	if got != "default_val" {
		t.Errorf("getEnv with empty env = %q, want default_val", got)
	}
}

// ---------------------------------------------------------------------------
// displayHealthMetrics
// ---------------------------------------------------------------------------

func TestDisplayHealthMetrics_NoOutput_NoPanic(t *testing.T) {
	// Redirect stdout to /dev/null; displayHealthMetrics writes to os.Stdout directly.
	origStdout := os.Stdout
	devNull, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatalf("open /dev/null: %v", err)
	}
	defer devNull.Close() //nolint:errcheck
	os.Stdout = devNull
	defer func() { os.Stdout = origStdout }()

	metrics := &health.HealthMetrics{
		MemoryUsage: health.MemoryStats{
			Alloc:       1024 * 1024,
			HeapAlloc:   512 * 1024,
			Sys:         2 * 1024 * 1024,
			HeapSys:     1024 * 1024,
			HeapIdle:    256 * 1024,
			HeapInuse:   256 * 1024,
			HeapObjects: 500,
			NumGC:       3,
			NextGC:      2 * 1024 * 1024,
		},
		CPUStats: health.CPUStats{
			Goroutines: 10,
			CgoCalls:   5,
		},
		DatabaseStats: health.DatabaseStats{
			OpenConnections:   2,
			InUse:             1,
			Idle:              1,
			WaitCount:         0,
			WaitDuration:      0,
			MaxIdleClosed:     0,
			MaxLifetimeClosed: 0,
		},
		Uptime:     5 * time.Minute,
		GoVersion:  "go1.24",
		Timestamp:  time.Now(),
		Goroutines: 10,
	}
	queryMetrics := health.QueryMetrics{
		QueryCount:    100,
		TotalDuration: 500 * time.Millisecond,
		AvgDuration:   5 * time.Millisecond,
		SlowQueries:   2,
	}

	// Must not panic.
	displayHealthMetrics(metrics, &queryMetrics)
}

// ---------------------------------------------------------------------------
// persistentPostRun — context carries no DBClassKey → returns nil.
// ---------------------------------------------------------------------------

func TestPersistentPostRun_NoDBInContext(t *testing.T) {
	cmd := &cobra.Command{}
	cmd.SetContext(context.Background())
	err := persistentPostRun(cmd, []string{})
	if err != nil {
		t.Errorf("persistentPostRun with no DB in context returned error: %v", err)
	}
}

// ---------------------------------------------------------------------------
// serveCmd — must override the root PersistentPreRunE so "serve" does not
// duplicate bootstrap.Boot's own DB/ServiceContainer initialization.
// ---------------------------------------------------------------------------

func TestServeCmd_OverridesRootPersistentPreRun(t *testing.T) {
	assert.NotNil(t, serveCmd.PersistentPreRunE,
		"serve must override the root pre-run so it does not build a throwaway DB connection and ServiceContainer")
}

func TestServePreRun_SetsLoggerInContext(t *testing.T) {
	cmd := &cobra.Command{Use: "serve"}
	cmd.SetContext(context.Background())

	err := servePreRun(cmd, []string{})
	if err != nil {
		t.Fatalf("servePreRun returned error: %v", err)
	}

	log, ok := cmd.Context().Value(common.LogKey).(*logging.Logger)
	assert.True(t, ok, "servePreRun must set common.LogKey in the context")
	assert.NotNil(t, log)
}

// ---------------------------------------------------------------------------
// resolveVault (thin wrapper around common.ResolveVaultName)
// ---------------------------------------------------------------------------

func TestResolveVault_DelegatesToCommon(t *testing.T) {
	os.Unsetenv("ROCKETVAULT_VAULT") //nolint:errcheck

	cmd := &cobra.Command{}
	cmd.Flags().String("vault", "", "")
	cmd.Flags().Set("vault", "my-vault") //nolint:errcheck,gosec

	got := resolveVault(cmd)
	if got != "my-vault" {
		t.Errorf("resolveVault = %q, want my-vault", got)
	}
}

// ---------------------------------------------------------------------------
// createMigration — uses a real temp directory to avoid DB dependency.
// ---------------------------------------------------------------------------

func TestCreateMigration_CreatesFile(t *testing.T) {
	origDir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	tmpDir := t.TempDir()
	migrDir := filepath.Join(tmpDir, "internal", "db", "migrations")
	if err := os.MkdirAll(migrDir, 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := os.Chdir(tmpDir); err != nil {
		t.Fatalf("chdir: %v", err)
	}
	defer os.Chdir(origDir) //nolint:errcheck

	cmd := &cobra.Command{}
	err = createMigration(cmd, []string{"add", "column", "to", "users"})
	if err != nil {
		t.Fatalf("createMigration returned error: %v", err)
	}

	entries, err := os.ReadDir(migrDir)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected 1 migration file, got %d", len(entries))
	}
	if filepath.Ext(entries[0].Name()) != ".sql" {
		t.Errorf("expected .sql extension, got %q", entries[0].Name())
	}
}

// ---------------------------------------------------------------------------
// runVersionList
// ---------------------------------------------------------------------------

func TestRunVersionList_InvalidSecretID(t *testing.T) {
	tc := testutils.NewTestContext(t)
	versionSecretID = "not-a-uuid"

	cmd := &cobra.Command{Use: "list", RunE: versionListCmd.RunE}
	cmd.Flags().StringVar(&versionSecretID, "secret-id", "not-a-uuid", "")
	cmd.SetContext(context.WithValue(tc.Ctx, common.UserIDKey, tc.TestUserID))

	err := cmd.RunE(cmd, []string{})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid secret ID")
}

func TestRunVersionList_ServiceContainerMissing(t *testing.T) {
	sid := uuid.New()
	versionSecretID = sid.String()

	ctx := context.WithValue(context.Background(), common.UserIDKey, uuid.New())

	cmd := &cobra.Command{Use: "list", RunE: versionListCmd.RunE}
	cmd.Flags().StringVar(&versionSecretID, "secret-id", sid.String(), "")
	cmd.SetContext(ctx)

	err := cmd.RunE(cmd, []string{})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "service container not available")
}

func TestRunVersionList_EmptyVersions(t *testing.T) {
	tc := testutils.NewTestContext(t)
	sID := uuid.New()

	// Metadata, not values, and a vault scope rather than an owner scope:
	// listing versions is authorized by ActionSecretsReadMetadata and must not
	// disclose values (docs/known-bugs.md § B30), and an owner scope would
	// survive revocation of the caller's access to the vault.
	tc.MockSecretService.On("GetSecretVersionsMetadata", mock.Anything, sID, mock.Anything).
		Return([]model.SecretVersionMetadata{}, nil)
	tc.MockContainer.On("GetSecretService").Return(tc.MockSecretService)

	versionSecretID = sID.String()

	var out bytes.Buffer
	cmd := &cobra.Command{Use: "list", RunE: versionListCmd.RunE}
	cmd.Flags().StringVar(&versionSecretID, "secret-id", sID.String(), "")
	cmd.SetContext(context.WithValue(tc.Ctx, common.UserIDKey, tc.TestUserID))
	cmd.SetOut(&out)

	err := cmd.RunE(cmd, []string{})
	assert.NoError(t, err)
	assert.Contains(t, out.String(), "No versions found")
}

func TestRunVersionList_ServiceReturnsError(t *testing.T) {
	tc := testutils.NewTestContext(t)
	sID := uuid.New()

	tc.MockSecretService.On("GetSecretVersionsMetadata", mock.Anything, sID, mock.Anything).
		Return(nil, fmt.Errorf("db error"))
	tc.MockContainer.On("GetSecretService").Return(tc.MockSecretService)

	versionSecretID = sID.String()

	cmd := &cobra.Command{Use: "list", RunE: versionListCmd.RunE}
	cmd.Flags().StringVar(&versionSecretID, "secret-id", sID.String(), "")
	cmd.SetContext(context.WithValue(tc.Ctx, common.UserIDKey, tc.TestUserID))

	err := cmd.RunE(cmd, []string{})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to get versions")
}

// ---------------------------------------------------------------------------
// runVersionGet
// ---------------------------------------------------------------------------

func TestRunVersionGet_InvalidSecretID(t *testing.T) {
	tc := testutils.NewTestContext(t)
	versionSecretID = "bad-uuid"
	versionNumber = 1

	cmd := &cobra.Command{Use: "get", RunE: versionGetCmd.RunE}
	cmd.Flags().StringVar(&versionSecretID, "secret-id", "bad-uuid", "")
	cmd.Flags().IntVar(&versionNumber, "version", 1, "")
	cmd.SetContext(context.WithValue(tc.Ctx, common.UserIDKey, tc.TestUserID))

	err := cmd.RunE(cmd, []string{})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid secret ID")
}

func TestRunVersionGet_ServiceContainerMissing(t *testing.T) {
	sid := uuid.New()
	versionSecretID = sid.String()
	versionNumber = 1

	ctx := context.WithValue(context.Background(), common.UserIDKey, uuid.New())

	cmd := &cobra.Command{Use: "get", RunE: versionGetCmd.RunE}
	cmd.Flags().StringVar(&versionSecretID, "secret-id", sid.String(), "")
	cmd.Flags().IntVar(&versionNumber, "version", 1, "")
	cmd.SetContext(ctx)

	err := cmd.RunE(cmd, []string{})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "service container not available")
}

func TestRunVersionGet_ServiceReturnsError(t *testing.T) {
	tc := testutils.NewTestContext(t)
	sID := uuid.New()
	versionSecretID = sID.String()
	versionNumber = 99

	tc.MockSecretService.On("GetSecretVersion", mock.Anything, sID, 99, mock.Anything).
		Return(nil, fmt.Errorf("not found"))
	tc.MockContainer.On("GetSecretService").Return(tc.MockSecretService)

	cmd := &cobra.Command{Use: "get", RunE: versionGetCmd.RunE}
	cmd.Flags().StringVar(&versionSecretID, "secret-id", sID.String(), "")
	cmd.Flags().IntVar(&versionNumber, "version", 99, "")
	cmd.SetContext(context.WithValue(tc.Ctx, common.UserIDKey, tc.TestUserID))

	err := cmd.RunE(cmd, []string{})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to get version")
}

// ---------------------------------------------------------------------------
// runVersionLatest
// ---------------------------------------------------------------------------

func TestRunVersionLatest_InvalidSecretID(t *testing.T) {
	tc := testutils.NewTestContext(t)
	versionSecretID = "not-valid"

	cmd := &cobra.Command{Use: "latest", RunE: versionLatestCmd.RunE}
	cmd.Flags().StringVar(&versionSecretID, "secret-id", "not-valid", "")
	cmd.SetContext(context.WithValue(tc.Ctx, common.UserIDKey, tc.TestUserID))

	err := cmd.RunE(cmd, []string{})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid secret ID")
}

func TestRunVersionLatest_ServiceContainerMissing(t *testing.T) {
	sid := uuid.New()
	versionSecretID = sid.String()

	ctx := context.WithValue(context.Background(), common.UserIDKey, uuid.New())

	cmd := &cobra.Command{Use: "latest", RunE: versionLatestCmd.RunE}
	cmd.Flags().StringVar(&versionSecretID, "secret-id", sid.String(), "")
	cmd.SetContext(ctx)

	err := cmd.RunE(cmd, []string{})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "service container not available")
}

func TestRunVersionLatest_ServiceReturnsError(t *testing.T) {
	tc := testutils.NewTestContext(t)
	sID := uuid.New()
	versionSecretID = sID.String()

	tc.MockSecretService.On("GetLatestSecretVersion", mock.Anything, sID, mock.Anything).
		Return(nil, fmt.Errorf("db error"))
	tc.MockContainer.On("GetSecretService").Return(tc.MockSecretService)

	cmd := &cobra.Command{Use: "latest", RunE: versionLatestCmd.RunE}
	cmd.Flags().StringVar(&versionSecretID, "secret-id", sID.String(), "")
	cmd.SetContext(context.WithValue(tc.Ctx, common.UserIDKey, tc.TestUserID))

	err := cmd.RunE(cmd, []string{})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to get latest version")
}

// rotationCtxMissingServiceContainer builds a context carrying valid
// authentication claims (so the rotation subcommand's claims check passes)
// but no service container, to exercise the "service container not
// available" branch that runs after vault-authorization setup but before the
// vault lookup itself.
func rotationCtxMissingServiceContainer() context.Context {
	userID := uuid.New()
	ctx := context.WithValue(context.Background(), common.UserIDKey, userID)
	return context.WithValue(ctx, common.ClaimsKey, &model.Claims{UserID: userID})
}

// ---------------------------------------------------------------------------
// runRotationCreate
// ---------------------------------------------------------------------------

func TestRunRotationCreate_ServiceContainerMissing(t *testing.T) {
	policyName = "test"
	policyInterval = 30
	policyReminder = 7
	policyAutoRotate = false
	policyDescription = ""

	ctx := rotationCtxMissingServiceContainer()

	cmd := &cobra.Command{Use: "create", RunE: rotationCreateCmd.RunE}
	cmd.SetContext(ctx)

	err := cmd.RunE(cmd, []string{})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "service container not available")
}

func TestRunRotationCreate_ServiceReturnsError(t *testing.T) {
	tc, mockRotSvc := setupRotationTestContext(t)

	mockRotSvc.On("CreatePolicy", mock.Anything, mock.AnythingOfType("secrets.CreatePolicyRequest")).
		Return(nil, fmt.Errorf("db error"))

	policyName = "failing-policy"
	policyInterval = 30
	policyReminder = 7
	policyAutoRotate = false
	policyDescription = ""

	cmd := &cobra.Command{Use: "create", RunE: rotationCreateCmd.RunE}
	cmd.SetContext(tc.Ctx)

	err := cmd.RunE(cmd, []string{})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to create rotation policy")
	mockRotSvc.AssertExpectations(t)
}

// ---------------------------------------------------------------------------
// runRotationList
// ---------------------------------------------------------------------------

func TestRunRotationList_ServiceContainerMissing(t *testing.T) {
	ctx := rotationCtxMissingServiceContainer()

	cmd := &cobra.Command{Use: "list", RunE: rotationListCmd.RunE}
	cmd.SetContext(ctx)

	err := cmd.RunE(cmd, []string{})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "service container not available")
}

func TestRunRotationList_ServiceReturnsError(t *testing.T) {
	tc, mockRotSvc := setupRotationTestContext(t)

	mockRotSvc.On("ListPolicies", mock.Anything, model.NewVaultScope(tc.TestVaultID, tc.TestUserID)).
		Return(nil, fmt.Errorf("db error"))

	cmd := &cobra.Command{Use: "list", RunE: rotationListCmd.RunE}
	cmd.SetContext(tc.Ctx)

	err := cmd.RunE(cmd, []string{})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to list rotation policies")
}

func TestRunRotationList_WithPolicies(t *testing.T) {
	tc, mockRotSvc := setupRotationTestContext(t)

	mockRotSvc.On("ListPolicies", mock.Anything, model.NewVaultScope(tc.TestVaultID, tc.TestUserID)).
		Return([]model.RotationPolicy{
			{ID: uuid.New(), Name: "pol-1", IntervalDays: 30, AutoRotate: false, Enabled: true, CreatedAt: time.Now()},
		}, nil)

	var out bytes.Buffer
	cmd := &cobra.Command{Use: "list", RunE: rotationListCmd.RunE}
	cmd.SetContext(tc.Ctx)
	cmd.SetOut(&out)

	err := cmd.RunE(cmd, []string{})
	assert.NoError(t, err)
	assert.Contains(t, out.String(), "pol-1")
	mockRotSvc.AssertExpectations(t)
}

// ---------------------------------------------------------------------------
// runRotationUpdate
// ---------------------------------------------------------------------------

func TestRunRotationUpdate_Success(t *testing.T) {
	tc, mockRotSvc := setupRotationTestContext(t)
	pid := uuid.New()

	existing := &model.RotationPolicy{
		ID:           pid,
		Name:         "old-name",
		Description:  "old-desc",
		IntervalDays: 30,
		ReminderDays: 7,
		AutoRotate:   false,
		Enabled:      true,
	}

	mockRotSvc.On("GetPolicy", mock.Anything, pid, model.NewVaultScope(tc.TestVaultID, tc.TestUserID)).Return(existing, nil)
	mockRotSvc.On("UpdatePolicy", mock.Anything, mock.MatchedBy(func(r secretServices.UpdatePolicyRequest) bool {
		return r.ID == pid && r.Name == "new-name"
	})).Return(&model.RotationPolicy{ID: pid, Name: "new-name"}, nil)

	policyID = pid.String()
	policyName = "new-name"

	var out bytes.Buffer
	cmd := &cobra.Command{Use: "update", RunE: rotationUpdateCmd.RunE}
	cmd.Flags().StringVar(&policyID, "id", pid.String(), "")
	cmd.Flags().StringVar(&policyName, "name", "new-name", "")
	cmd.Flags().StringVar(&policyDescription, "description", "", "")
	cmd.Flags().IntVar(&policyInterval, "interval", 0, "")
	cmd.Flags().IntVar(&policyReminder, "reminder", 0, "")
	cmd.Flags().BoolVar(&policyAutoRotate, "auto-rotate", false, "")
	cmd.Flags().Set("name", "new-name") //nolint:errcheck,gosec
	cmd.SetContext(tc.Ctx)
	cmd.SetOut(&out)

	err := cmd.RunE(cmd, []string{})
	assert.NoError(t, err)
	assert.Contains(t, out.String(), "updated successfully")
	mockRotSvc.AssertExpectations(t)
}

func TestRunRotationUpdate_AllFlagsChanged(t *testing.T) {
	tc, mockRotSvc := setupRotationTestContext(t)
	pid := uuid.New()

	existing := &model.RotationPolicy{
		ID:           pid,
		Name:         "old-name",
		Description:  "old-desc",
		IntervalDays: 30,
		ReminderDays: 7,
		AutoRotate:   false,
		Enabled:      true,
	}

	mockRotSvc.On("GetPolicy", mock.Anything, pid, model.NewVaultScope(tc.TestVaultID, tc.TestUserID)).Return(existing, nil)
	mockRotSvc.On("UpdatePolicy", mock.Anything, mock.MatchedBy(func(r secretServices.UpdatePolicyRequest) bool {
		return r.ID == pid && r.Name == "new-name" && r.IntervalDays == 60 &&
			r.ReminderDays == 14 && r.AutoRotate == true
	})).Return(&model.RotationPolicy{ID: pid, Name: "new-name"}, nil)

	policyID = pid.String()

	var out bytes.Buffer
	cmd := &cobra.Command{Use: "update", RunE: rotationUpdateCmd.RunE}
	cmd.Flags().StringVar(&policyID, "id", pid.String(), "")
	cmd.Flags().StringVar(&policyName, "name", "new-name", "")
	cmd.Flags().StringVar(&policyDescription, "description", "new-desc", "")
	cmd.Flags().IntVar(&policyInterval, "interval", 60, "")
	cmd.Flags().IntVar(&policyReminder, "reminder", 14, "")
	cmd.Flags().BoolVar(&policyAutoRotate, "auto-rotate", true, "")
	// Mark all as changed.
	cmd.Flags().Set("name", "new-name")        //nolint:errcheck,gosec
	cmd.Flags().Set("description", "new-desc") //nolint:errcheck,gosec
	cmd.Flags().Set("interval", "60")          //nolint:errcheck,gosec
	cmd.Flags().Set("reminder", "14")          //nolint:errcheck,gosec
	cmd.Flags().Set("auto-rotate", "true")     //nolint:errcheck,gosec
	cmd.SetContext(tc.Ctx)
	cmd.SetOut(&out)

	err := cmd.RunE(cmd, []string{})
	assert.NoError(t, err)
	mockRotSvc.AssertExpectations(t)
}

func TestRunRotationUpdate_GetPolicyError(t *testing.T) {
	tc, mockRotSvc := setupRotationTestContext(t)
	pid := uuid.New()

	mockRotSvc.On("GetPolicy", mock.Anything, pid, model.NewVaultScope(tc.TestVaultID, tc.TestUserID)).Return(nil, fmt.Errorf("not found"))

	policyID = pid.String()

	cmd := &cobra.Command{Use: "update", RunE: rotationUpdateCmd.RunE}
	cmd.Flags().StringVar(&policyID, "id", pid.String(), "")
	cmd.Flags().StringVar(&policyName, "name", "", "")
	cmd.Flags().StringVar(&policyDescription, "description", "", "")
	cmd.Flags().IntVar(&policyInterval, "interval", 0, "")
	cmd.Flags().IntVar(&policyReminder, "reminder", 0, "")
	cmd.Flags().BoolVar(&policyAutoRotate, "auto-rotate", false, "")
	cmd.SetContext(tc.Ctx)

	err := cmd.RunE(cmd, []string{})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to read policy")
}

func TestRunRotationUpdate_UpdatePolicyError(t *testing.T) {
	tc, mockRotSvc := setupRotationTestContext(t)
	pid := uuid.New()

	existing := &model.RotationPolicy{
		ID: pid, Name: "old", IntervalDays: 30, Enabled: true,
	}

	mockRotSvc.On("GetPolicy", mock.Anything, pid, model.NewVaultScope(tc.TestVaultID, tc.TestUserID)).Return(existing, nil)
	mockRotSvc.On("UpdatePolicy", mock.Anything, mock.AnythingOfType("secrets.UpdatePolicyRequest")).
		Return(nil, fmt.Errorf("db error"))

	policyID = pid.String()

	cmd := &cobra.Command{Use: "update", RunE: rotationUpdateCmd.RunE}
	cmd.Flags().StringVar(&policyID, "id", pid.String(), "")
	cmd.Flags().StringVar(&policyName, "name", "", "")
	cmd.Flags().StringVar(&policyDescription, "description", "", "")
	cmd.Flags().IntVar(&policyInterval, "interval", 0, "")
	cmd.Flags().IntVar(&policyReminder, "reminder", 0, "")
	cmd.Flags().BoolVar(&policyAutoRotate, "auto-rotate", false, "")
	cmd.SetContext(tc.Ctx)

	err := cmd.RunE(cmd, []string{})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to update rotation policy")
}

func TestRunRotationUpdate_InvalidPolicyID(t *testing.T) {
	tc, _ := setupRotationTestContext(t)
	policyID = "bad-uuid"

	cmd := &cobra.Command{Use: "update", RunE: rotationUpdateCmd.RunE}
	cmd.Flags().StringVar(&policyID, "id", "bad-uuid", "")
	cmd.Flags().StringVar(&policyName, "name", "", "")
	cmd.Flags().StringVar(&policyDescription, "description", "", "")
	cmd.Flags().IntVar(&policyInterval, "interval", 0, "")
	cmd.Flags().IntVar(&policyReminder, "reminder", 0, "")
	cmd.Flags().BoolVar(&policyAutoRotate, "auto-rotate", false, "")
	cmd.SetContext(tc.Ctx)

	err := cmd.RunE(cmd, []string{})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid policy ID")
}

func TestRunRotationUpdate_ServiceContainerMissing(t *testing.T) {
	pid := uuid.New()
	policyID = pid.String()
	ctx := rotationCtxMissingServiceContainer()

	cmd := &cobra.Command{Use: "update", RunE: rotationUpdateCmd.RunE}
	cmd.Flags().StringVar(&policyID, "id", pid.String(), "")
	cmd.Flags().StringVar(&policyName, "name", "", "")
	cmd.Flags().StringVar(&policyDescription, "description", "", "")
	cmd.Flags().IntVar(&policyInterval, "interval", 0, "")
	cmd.Flags().IntVar(&policyReminder, "reminder", 0, "")
	cmd.Flags().BoolVar(&policyAutoRotate, "auto-rotate", false, "")
	cmd.SetContext(ctx)

	err := cmd.RunE(cmd, []string{})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "service container not available")
}

// ---------------------------------------------------------------------------
// runRotationDelete
// ---------------------------------------------------------------------------

func TestRunRotationDelete_Success(t *testing.T) {
	tc, mockRotSvc := setupRotationTestContext(t)
	pid := uuid.New()

	mockRotSvc.On("DeletePolicy", mock.Anything, pid, model.NewVaultScope(tc.TestVaultID, tc.TestUserID)).Return(nil)
	policyID = pid.String()

	var out bytes.Buffer
	cmd := &cobra.Command{Use: "delete", RunE: rotationDeleteCmd.RunE}
	cmd.Flags().StringVar(&policyID, "id", pid.String(), "")
	cmd.SetContext(tc.Ctx)
	cmd.SetOut(&out)

	err := cmd.RunE(cmd, []string{})
	assert.NoError(t, err)
	assert.Contains(t, out.String(), "deleted successfully")
	mockRotSvc.AssertExpectations(t)
}

func TestRunRotationDelete_ServiceReturnsError(t *testing.T) {
	tc, mockRotSvc := setupRotationTestContext(t)
	pid := uuid.New()

	mockRotSvc.On("DeletePolicy", mock.Anything, pid, model.NewVaultScope(tc.TestVaultID, tc.TestUserID)).Return(fmt.Errorf("forbidden"))
	policyID = pid.String()

	cmd := &cobra.Command{Use: "delete", RunE: rotationDeleteCmd.RunE}
	cmd.Flags().StringVar(&policyID, "id", pid.String(), "")
	cmd.SetContext(tc.Ctx)

	err := cmd.RunE(cmd, []string{})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to delete rotation policy")
}

func TestRunRotationDelete_InvalidPolicyID(t *testing.T) {
	tc, _ := setupRotationTestContext(t)
	policyID = "not-a-uuid"

	cmd := &cobra.Command{Use: "delete", RunE: rotationDeleteCmd.RunE}
	cmd.Flags().StringVar(&policyID, "id", "not-a-uuid", "")
	cmd.SetContext(tc.Ctx)

	err := cmd.RunE(cmd, []string{})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid policy ID")
}

func TestRunRotationDelete_ServiceContainerMissing(t *testing.T) {
	pid := uuid.New()
	policyID = pid.String()
	ctx := rotationCtxMissingServiceContainer()

	cmd := &cobra.Command{Use: "delete", RunE: rotationDeleteCmd.RunE}
	cmd.Flags().StringVar(&policyID, "id", pid.String(), "")
	cmd.SetContext(ctx)

	err := cmd.RunE(cmd, []string{})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "service container not available")
}

// ---------------------------------------------------------------------------
// runRotationAssign
// ---------------------------------------------------------------------------

func TestRunRotationAssign_Success(t *testing.T) {
	tc, mockRotSvc := setupRotationTestContext(t)
	pid := uuid.New()
	sid := uuid.New()

	mockRotSvc.On("AssignPolicyToSecret", mock.Anything, mock.MatchedBy(func(r secretServices.AssignPolicyRequest) bool {
		return r.PolicyID == pid && r.SecretID == sid && r.Scope == model.NewVaultScope(tc.TestVaultID, tc.TestUserID)
	})).Return(nil)

	policyID = pid.String()
	secretID = sid.String()

	var out bytes.Buffer
	cmd := &cobra.Command{Use: "assign", RunE: rotationAssignCmd.RunE}
	cmd.Flags().StringVar(&policyID, "policy-id", pid.String(), "")
	cmd.Flags().StringVar(&secretID, "secret-id", sid.String(), "")
	cmd.SetContext(tc.Ctx)
	cmd.SetOut(&out)

	err := cmd.RunE(cmd, []string{})
	assert.NoError(t, err)
	assert.Contains(t, out.String(), "assigned")
	mockRotSvc.AssertExpectations(t)
}

func TestRunRotationAssign_ServiceReturnsError(t *testing.T) {
	tc, mockRotSvc := setupRotationTestContext(t)
	pid := uuid.New()
	sid := uuid.New()

	mockRotSvc.On("AssignPolicyToSecret", mock.Anything, mock.AnythingOfType("secrets.AssignPolicyRequest")).
		Return(fmt.Errorf("db error"))

	policyID = pid.String()
	secretID = sid.String()

	cmd := &cobra.Command{Use: "assign", RunE: rotationAssignCmd.RunE}
	cmd.Flags().StringVar(&policyID, "policy-id", pid.String(), "")
	cmd.Flags().StringVar(&secretID, "secret-id", sid.String(), "")
	cmd.SetContext(tc.Ctx)

	err := cmd.RunE(cmd, []string{})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to assign policy")
}

func TestRunRotationAssign_InvalidPolicyID(t *testing.T) {
	tc, _ := setupRotationTestContext(t)
	policyID = "bad"
	secretID = uuid.New().String()

	cmd := &cobra.Command{Use: "assign", RunE: rotationAssignCmd.RunE}
	cmd.Flags().StringVar(&policyID, "policy-id", "bad", "")
	cmd.Flags().StringVar(&secretID, "secret-id", secretID, "")
	cmd.SetContext(tc.Ctx)

	err := cmd.RunE(cmd, []string{})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid policy ID")
}

func TestRunRotationAssign_InvalidSecretID(t *testing.T) {
	tc, _ := setupRotationTestContext(t)
	policyID = uuid.New().String()
	secretID = "bad"

	cmd := &cobra.Command{Use: "assign", RunE: rotationAssignCmd.RunE}
	cmd.Flags().StringVar(&policyID, "policy-id", policyID, "")
	cmd.Flags().StringVar(&secretID, "secret-id", "bad", "")
	cmd.SetContext(tc.Ctx)

	err := cmd.RunE(cmd, []string{})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid secret ID")
}

func TestRunRotationAssign_ServiceContainerMissing(t *testing.T) {
	pid := uuid.New()
	sid := uuid.New()
	policyID = pid.String()
	secretID = sid.String()
	ctx := rotationCtxMissingServiceContainer()

	cmd := &cobra.Command{Use: "assign", RunE: rotationAssignCmd.RunE}
	cmd.Flags().StringVar(&policyID, "policy-id", pid.String(), "")
	cmd.Flags().StringVar(&secretID, "secret-id", sid.String(), "")
	cmd.SetContext(ctx)

	err := cmd.RunE(cmd, []string{})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "service container not available")
}

// ---------------------------------------------------------------------------
// runRotationUnassign
// ---------------------------------------------------------------------------

func TestRunRotationUnassign_Success(t *testing.T) {
	tc, mockRotSvc := setupRotationTestContext(t)
	pid := uuid.New()
	sid := uuid.New()

	mockRotSvc.On("RemovePolicyFromSecret", mock.Anything, sid, pid, model.NewVaultScope(tc.TestVaultID, tc.TestUserID)).Return(nil)
	policyID = pid.String()
	secretID = sid.String()

	var out bytes.Buffer
	cmd := &cobra.Command{Use: "unassign", RunE: rotationUnassignCmd.RunE}
	cmd.Flags().StringVar(&policyID, "policy-id", pid.String(), "")
	cmd.Flags().StringVar(&secretID, "secret-id", sid.String(), "")
	cmd.SetContext(tc.Ctx)
	cmd.SetOut(&out)

	err := cmd.RunE(cmd, []string{})
	assert.NoError(t, err)
	assert.Contains(t, out.String(), "removed")
	mockRotSvc.AssertExpectations(t)
}

func TestRunRotationUnassign_ServiceReturnsError(t *testing.T) {
	tc, mockRotSvc := setupRotationTestContext(t)
	pid := uuid.New()
	sid := uuid.New()

	mockRotSvc.On("RemovePolicyFromSecret", mock.Anything, sid, pid, model.NewVaultScope(tc.TestVaultID, tc.TestUserID)).
		Return(fmt.Errorf("forbidden"))
	policyID = pid.String()
	secretID = sid.String()

	cmd := &cobra.Command{Use: "unassign", RunE: rotationUnassignCmd.RunE}
	cmd.Flags().StringVar(&policyID, "policy-id", pid.String(), "")
	cmd.Flags().StringVar(&secretID, "secret-id", sid.String(), "")
	cmd.SetContext(tc.Ctx)

	err := cmd.RunE(cmd, []string{})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to remove policy")
}

func TestRunRotationUnassign_InvalidPolicyID(t *testing.T) {
	tc, _ := setupRotationTestContext(t)
	policyID = "bad"
	secretID = uuid.New().String()

	cmd := &cobra.Command{Use: "unassign", RunE: rotationUnassignCmd.RunE}
	cmd.Flags().StringVar(&policyID, "policy-id", "bad", "")
	cmd.Flags().StringVar(&secretID, "secret-id", secretID, "")
	cmd.SetContext(tc.Ctx)

	err := cmd.RunE(cmd, []string{})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid policy ID")
}

func TestRunRotationUnassign_InvalidSecretID(t *testing.T) {
	tc, _ := setupRotationTestContext(t)
	policyID = uuid.New().String()
	secretID = "bad"

	cmd := &cobra.Command{Use: "unassign", RunE: rotationUnassignCmd.RunE}
	cmd.Flags().StringVar(&policyID, "policy-id", policyID, "")
	cmd.Flags().StringVar(&secretID, "secret-id", "bad", "")
	cmd.SetContext(tc.Ctx)

	err := cmd.RunE(cmd, []string{})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid secret ID")
}

func TestRunRotationUnassign_ServiceContainerMissing(t *testing.T) {
	pid := uuid.New()
	sid := uuid.New()
	policyID = pid.String()
	secretID = sid.String()
	ctx := rotationCtxMissingServiceContainer()

	cmd := &cobra.Command{Use: "unassign", RunE: rotationUnassignCmd.RunE}
	cmd.Flags().StringVar(&policyID, "policy-id", pid.String(), "")
	cmd.Flags().StringVar(&secretID, "secret-id", sid.String(), "")
	cmd.SetContext(ctx)

	err := cmd.RunE(cmd, []string{})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "service container not available")
}

// ---------------------------------------------------------------------------
// runRotationHistory
// ---------------------------------------------------------------------------

func TestRunRotationHistory_EmptyHistory(t *testing.T) {
	tc, mockRotSvc := setupRotationTestContext(t)
	sid := uuid.New()

	mockRotSvc.On("GetRotationHistory", mock.Anything, sid, model.NewVaultScope(tc.TestVaultID, tc.TestUserID)).
		Return([]model.RotationHistory{}, nil)
	secretID = sid.String()

	var out bytes.Buffer
	cmd := &cobra.Command{Use: "history", RunE: rotationHistoryCmd.RunE}
	cmd.Flags().StringVar(&secretID, "secret-id", sid.String(), "")
	cmd.SetContext(tc.Ctx)
	cmd.SetOut(&out)

	err := cmd.RunE(cmd, []string{})
	assert.NoError(t, err)
	assert.Contains(t, out.String(), "No rotation history found")
	mockRotSvc.AssertExpectations(t)
}

func TestRunRotationHistory_WithEntries(t *testing.T) {
	tc, mockRotSvc := setupRotationTestContext(t)
	sid := uuid.New()

	history := []model.RotationHistory{
		{
			SecretID:        sid,
			RotatedAt:       time.Now(),
			TriggeredBy:     "manual",
			PreviousVersion: 1,
			NewVersion:      2,
			Notes:           "rotated manually",
		},
	}
	mockRotSvc.On("GetRotationHistory", mock.Anything, sid, model.NewVaultScope(tc.TestVaultID, tc.TestUserID)).Return(history, nil)
	secretID = sid.String()

	var out bytes.Buffer
	cmd := &cobra.Command{Use: "history", RunE: rotationHistoryCmd.RunE}
	cmd.Flags().StringVar(&secretID, "secret-id", sid.String(), "")
	cmd.SetContext(tc.Ctx)
	cmd.SetOut(&out)

	err := cmd.RunE(cmd, []string{})
	assert.NoError(t, err)
	assert.Contains(t, out.String(), "manual")
	mockRotSvc.AssertExpectations(t)
}

func TestRunRotationHistory_LongNotesTruncated(t *testing.T) {
	tc, mockRotSvc := setupRotationTestContext(t)
	sid := uuid.New()

	// Notes longer than 30 chars should be truncated to 27 + "..."
	longNotes := "this is a very long note that exceeds thirty characters easily"
	history := []model.RotationHistory{
		{SecretID: sid, RotatedAt: time.Now(), TriggeredBy: "auto", Notes: longNotes},
	}
	mockRotSvc.On("GetRotationHistory", mock.Anything, sid, model.NewVaultScope(tc.TestVaultID, tc.TestUserID)).Return(history, nil)
	secretID = sid.String()

	var out bytes.Buffer
	cmd := &cobra.Command{Use: "history", RunE: rotationHistoryCmd.RunE}
	cmd.Flags().StringVar(&secretID, "secret-id", sid.String(), "")
	cmd.SetContext(tc.Ctx)
	cmd.SetOut(&out)

	err := cmd.RunE(cmd, []string{})
	assert.NoError(t, err)
	assert.Contains(t, out.String(), "...")
}

func TestRunRotationHistory_ServiceReturnsError(t *testing.T) {
	tc, mockRotSvc := setupRotationTestContext(t)
	sid := uuid.New()

	mockRotSvc.On("GetRotationHistory", mock.Anything, sid, model.NewVaultScope(tc.TestVaultID, tc.TestUserID)).
		Return(nil, fmt.Errorf("db error"))
	secretID = sid.String()

	cmd := &cobra.Command{Use: "history", RunE: rotationHistoryCmd.RunE}
	cmd.Flags().StringVar(&secretID, "secret-id", sid.String(), "")
	cmd.SetContext(tc.Ctx)

	err := cmd.RunE(cmd, []string{})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to get rotation history")
}

func TestRunRotationHistory_InvalidSecretID(t *testing.T) {
	tc, _ := setupRotationTestContext(t)
	secretID = "bad-uuid"

	cmd := &cobra.Command{Use: "history", RunE: rotationHistoryCmd.RunE}
	cmd.Flags().StringVar(&secretID, "secret-id", "bad-uuid", "")
	cmd.SetContext(tc.Ctx)

	err := cmd.RunE(cmd, []string{})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid secret ID")
}

func TestRunRotationHistory_ServiceContainerMissing(t *testing.T) {
	sid := uuid.New()
	secretID = sid.String()
	ctx := rotationCtxMissingServiceContainer()

	cmd := &cobra.Command{Use: "history", RunE: rotationHistoryCmd.RunE}
	cmd.Flags().StringVar(&secretID, "secret-id", sid.String(), "")
	cmd.SetContext(ctx)

	err := cmd.RunE(cmd, []string{})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "service container not available")
}

// ---------------------------------------------------------------------------
// runRotationStatus
// ---------------------------------------------------------------------------

func TestRunRotationStatus_NoDueRotations(t *testing.T) {
	tc, mockRotSvc := setupRotationTestContext(t)

	mockRotSvc.On("GetDueRotations", mock.Anything, model.NewVaultScope(tc.TestVaultID, tc.TestUserID)).
		Return([]model.SecretPolicy{}, nil)
	mockRotSvc.On("GetUpcomingReminders", mock.Anything, model.NewVaultScope(tc.TestVaultID, tc.TestUserID)).
		Return([]model.RotationReminder{}, nil)
	mockRotSvc.On("ListPolicies", mock.Anything, model.NewVaultScope(tc.TestVaultID, tc.TestUserID)).
		Return([]model.RotationPolicy{}, nil)

	var out bytes.Buffer
	cmd := &cobra.Command{Use: "status", RunE: rotationStatusCmd.RunE}
	cmd.SetContext(tc.Ctx)
	cmd.SetOut(&out)

	err := cmd.RunE(cmd, []string{})
	assert.NoError(t, err)
	assert.Contains(t, out.String(), "No secrets are currently due for rotation")
	mockRotSvc.AssertExpectations(t)
}

func TestRunRotationStatus_WithDueAndReminders(t *testing.T) {
	tc, mockRotSvc := setupRotationTestContext(t)
	sid := uuid.New()
	nextTime := time.Now().Add(24 * time.Hour)

	dueRotations := []model.SecretPolicy{
		{SecretID: sid, NextRotationAt: &nextTime},
	}
	reminders := []model.RotationReminder{
		{SecretID: sid, ReminderType: "7-day"},
	}
	policies := []model.RotationPolicy{
		{ID: uuid.New(), Name: "Monthly", IntervalDays: 30, AutoRotate: true, Enabled: true},
	}

	mockRotSvc.On("GetDueRotations", mock.Anything, model.NewVaultScope(tc.TestVaultID, tc.TestUserID)).Return(dueRotations, nil)
	mockRotSvc.On("GetUpcomingReminders", mock.Anything, model.NewVaultScope(tc.TestVaultID, tc.TestUserID)).Return(reminders, nil)
	mockRotSvc.On("ListPolicies", mock.Anything, model.NewVaultScope(tc.TestVaultID, tc.TestUserID)).Return(policies, nil)

	var out bytes.Buffer
	cmd := &cobra.Command{Use: "status", RunE: rotationStatusCmd.RunE}
	cmd.SetContext(tc.Ctx)
	cmd.SetOut(&out)

	err := cmd.RunE(cmd, []string{})
	assert.NoError(t, err)
	outStr := out.String()
	assert.Contains(t, outStr, "Secrets due for rotation")
	assert.Contains(t, outStr, "7-day")
	assert.Contains(t, outStr, "Monthly")
	mockRotSvc.AssertExpectations(t)
}

func TestRunRotationStatus_DueRotationNilNextTime(t *testing.T) {
	tc, mockRotSvc := setupRotationTestContext(t)
	sid := uuid.New()

	// NextRotationAt is nil — the "Unknown" branch should be exercised.
	dueRotations := []model.SecretPolicy{
		{SecretID: sid, NextRotationAt: nil},
	}

	mockRotSvc.On("GetDueRotations", mock.Anything, model.NewVaultScope(tc.TestVaultID, tc.TestUserID)).Return(dueRotations, nil)
	mockRotSvc.On("GetUpcomingReminders", mock.Anything, model.NewVaultScope(tc.TestVaultID, tc.TestUserID)).Return([]model.RotationReminder{}, nil)
	mockRotSvc.On("ListPolicies", mock.Anything, model.NewVaultScope(tc.TestVaultID, tc.TestUserID)).Return([]model.RotationPolicy{}, nil)

	var out bytes.Buffer
	cmd := &cobra.Command{Use: "status", RunE: rotationStatusCmd.RunE}
	cmd.SetContext(tc.Ctx)
	cmd.SetOut(&out)

	err := cmd.RunE(cmd, []string{})
	assert.NoError(t, err)
	assert.Contains(t, out.String(), "Unknown")
}

func TestRunRotationStatus_GetDueRotationsError(t *testing.T) {
	tc, mockRotSvc := setupRotationTestContext(t)

	mockRotSvc.On("GetDueRotations", mock.Anything, model.NewVaultScope(tc.TestVaultID, tc.TestUserID)).
		Return(nil, fmt.Errorf("db error"))

	cmd := &cobra.Command{Use: "status", RunE: rotationStatusCmd.RunE}
	cmd.SetContext(tc.Ctx)

	err := cmd.RunE(cmd, []string{})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to get due rotations")
}

func TestRunRotationStatus_GetUpcomingRemindersError(t *testing.T) {
	tc, mockRotSvc := setupRotationTestContext(t)

	mockRotSvc.On("GetDueRotations", mock.Anything, model.NewVaultScope(tc.TestVaultID, tc.TestUserID)).Return([]model.SecretPolicy{}, nil)
	mockRotSvc.On("GetUpcomingReminders", mock.Anything, model.NewVaultScope(tc.TestVaultID, tc.TestUserID)).Return(nil, fmt.Errorf("db error"))

	cmd := &cobra.Command{Use: "status", RunE: rotationStatusCmd.RunE}
	cmd.SetContext(tc.Ctx)

	err := cmd.RunE(cmd, []string{})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to get upcoming reminders")
}

func TestRunRotationStatus_ListUserPoliciesError(t *testing.T) {
	tc, mockRotSvc := setupRotationTestContext(t)

	mockRotSvc.On("GetDueRotations", mock.Anything, model.NewVaultScope(tc.TestVaultID, tc.TestUserID)).Return([]model.SecretPolicy{}, nil)
	mockRotSvc.On("GetUpcomingReminders", mock.Anything, model.NewVaultScope(tc.TestVaultID, tc.TestUserID)).Return([]model.RotationReminder{}, nil)
	mockRotSvc.On("ListPolicies", mock.Anything, model.NewVaultScope(tc.TestVaultID, tc.TestUserID)).Return(nil, fmt.Errorf("db error"))

	cmd := &cobra.Command{Use: "status", RunE: rotationStatusCmd.RunE}
	cmd.SetContext(tc.Ctx)

	err := cmd.RunE(cmd, []string{})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to list policies")
}

func TestRunRotationStatus_ServiceContainerMissing(t *testing.T) {
	ctx := rotationCtxMissingServiceContainer()

	cmd := &cobra.Command{Use: "status", RunE: rotationStatusCmd.RunE}
	cmd.SetContext(ctx)

	err := cmd.RunE(cmd, []string{})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "service container not available")
}

// ---------------------------------------------------------------------------
// runRotationRotate
// ---------------------------------------------------------------------------

func TestRunRotationRotate_InvalidSecretID(t *testing.T) {
	tc, _ := setupRotationTestContext(t)
	secretID = "bad"
	policyID = uuid.New().String()

	cmd := &cobra.Command{Use: "rotate", RunE: rotationRotateCmd.RunE}
	cmd.Flags().StringVar(&secretID, "secret-id", "bad", "")
	cmd.Flags().StringVar(&policyID, "policy-id", policyID, "")
	cmd.SetContext(tc.Ctx)

	err := cmd.RunE(cmd, []string{})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid secret ID")
}

func TestRunRotationRotate_InvalidPolicyID(t *testing.T) {
	tc, _ := setupRotationTestContext(t)
	secretID = uuid.New().String()
	policyID = "bad"

	cmd := &cobra.Command{Use: "rotate", RunE: rotationRotateCmd.RunE}
	cmd.Flags().StringVar(&secretID, "secret-id", secretID, "")
	cmd.Flags().StringVar(&policyID, "policy-id", "bad", "")
	cmd.SetContext(tc.Ctx)

	err := cmd.RunE(cmd, []string{})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid policy ID")
}

func TestRunRotationRotate_ServiceReturnsError(t *testing.T) {
	tc, mockRotSvc := setupRotationTestContext(t)
	sid := uuid.New()
	pid := uuid.New()

	mockRotSvc.On("PerformManualRotation", mock.Anything, mock.AnythingOfType("secrets.ManualRotationRequest")).
		Return(fmt.Errorf("rotation failed"))

	secretID = sid.String()
	policyID = pid.String()
	rotateValue = "operator-supplied"
	rotateGenerate = false
	t.Cleanup(func() { rotateValue = "" })

	cmd := &cobra.Command{Use: "rotate", RunE: rotationRotateCmd.RunE}
	cmd.Flags().StringVar(&secretID, "secret-id", sid.String(), "")
	cmd.Flags().StringVar(&policyID, "policy-id", pid.String(), "")
	cmd.SetContext(tc.Ctx)

	err := cmd.RunE(cmd, []string{})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to rotate secret")
}

// ---------------------------------------------------------------------------
// vault-provisioning registration
// ---------------------------------------------------------------------------

// TestRootCommand_HasVaultProvisioning proves the vault-provisioning command
// group is registered on the root command, mirroring the registration of
// vault-webhook and vault-access.
func TestRootCommand_HasVaultProvisioning(t *testing.T) {
	var found bool
	for _, c := range rootCmd.Commands() {
		if c.Name() == "vault-provisioning" {
			found = true
			break
		}
	}
	require.True(t, found, "vault-provisioning must be registered on the root command")
}

// TestVaultProvisioning_HasAllThreeSubcommands proves grant, revoke and list
// are all attached to the vault-provisioning parent command.
func TestVaultProvisioning_HasAllThreeSubcommands(t *testing.T) {
	names := map[string]bool{}
	for _, c := range vaultProvisioningCmd.Commands() {
		names[c.Name()] = true
	}
	require.True(t, names["grant"], "grant must be registered")
	require.True(t, names["revoke"], "revoke must be registered")
	require.True(t, names["list"], "list must be registered")
}
