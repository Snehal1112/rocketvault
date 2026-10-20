# Certificate Restore and Renewal Isolation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (- [ ]) syntax for tracking.

**Goal:** Stop a forged or cross-vault certificate backup from steering the auto-renew scheduler into other vaults, make certificate issuance and renewal respect the signing key's lifecycle and the `keys/sign` data action, and fix two small certificate-creation input and error-mapping defects.

**Architecture:** Per-item backup blobs become sealed (AES-256-GCM via `common.EncryptWithKey`, under a key derived from the master key with HKDF), so only blobs this server produced restore at all; `RestoreCertificate` additionally drops `key_id`/`ca_cert_id` links that do not resolve in the target vault, and the scheduler renews under `model.NewVaultScope(cert.VaultID, cert.UserID)` instead of an admin scope. Signing-key lifecycle is enforced in the certificate service (both the leaf key and the CA row's linked key), while the `keys/sign` requirement is enforced at the two authorization entry points (HTTP handler, CLI session) through one shared helper, `authorization.RequireDataPlaneAccess`, and re-checked by the scheduler for the certificate owner. Error mapping and the validity cap are small edits in `api/` plus a service-side guard so the CLI gets the same bound.

**Tech Stack:** Go 1.25 (`go.mod`), stdlib `crypto/hkdf` and `crypto/sha256`, Gorilla Mux, Cobra, testify, ozzo-validation.

**Spec:**
- Unfiled High finding (this plan files it as GitHub issue **B76** in Task 3): forged certificate restore blob plants cross-vault references that the auto-renew scheduler follows with an admin scope. Same class as `.claude/known-bugs.md` § B15 (restore wrote the blob's vault) and § B32 (certificate creation authorized its key by ownership, not vault).
- GitHub issue #43 (certificate create and renew ignore key lifecycle and do not require the sign action), tracked as **B77**.
- Two unfiled Low findings (filed as **B78** in Task 10): `createCertificate` maps every service error to 500; `validity_days` has no upper bound.
- Audit: static audit of `api/` on 2026-09-30 (quoted in issue #43).
- Precedent docs: `.claude/known-bugs.md` § B15, § B32, § B37 (CA link immutable in `Update`), § B43/B44 (CA keyCertSign fix), § B33 (CLI/HTTP policy-operation parity).

**Priority:** P1. **B-number range:** B76-B78.

**Prerequisite:** `docs/superpowers/plans/2026-09-30-authorization-policy-and-audit.md` must land first. Task 4 of this plan replaces `internal/services/authorization/data_action_authz.go` wholesale, and that plan changes `RoleAssignmentService.RevokeAssignment` to take an `actorID` and edits the `fakeRoleAssignmentService` double at `internal/services/authorization/data_action_authz_test.go:33`. Rebase onto it before starting: Task 4's new `data_plane_access_test.go` reuses that fake, so the fake must already carry the post-change `RevokeAssignment(ctx, assignmentID, vaultID, actorID uuid.UUID, callerIsGlobalAdmin bool)` signature, and the replaced `data_action_authz.go` must keep whatever that plan added to it.

**Breaking changes** (both go in the release note, Task 11):
1. A principal holding only `Key Vault Certificates Officer` can no longer issue certificates, on HTTP or CLI: issuing and renewing now also require `keys/sign`, so it needs `Key Vault Crypto User` (or Crypto Officer, or Administrator) in addition.
2. Auto-renew stops for certificates whose owner no longer holds `keys/sign` in the certificate's vault. The scheduler skips them and logs an audit failure instead of renewing; grant the owner a role carrying `keys/sign` to resume.

## Global Constraints

- Commits: invoke the `dev-workflow-skills:1-git-commit` plugin skill via the Skill tool. Never use a freeform `git commit -m`. All commits and tags are GPG signed (key 61D246B30285ED35).
- Code comments are short full sentences ending with a punctuation mark.
- Before any PR: `go build ./...`, `go vet ./...` and `go test ./...` must pass. golangci-lint currently fails locally (snap Go toolchain incompatibility), so lint must run in CI or on a fixed toolchain.
- CLI commands call the service layer directly and bypass HTTP middleware, so every behavior change is tested on the HTTP path and on the CLI path (`cmd/certificates`) or on the service the CLI calls.
- Repositories stay pure CRUD. No repository file changes in this plan; no schema change; no `internal/db/db.go` edit.
- Sealed blob format marker: the literal prefix `rvb2.`. HKDF info string: `rocketvault item-backup blob seal v2`. Derived key length: 32 bytes.
- Pre-upgrade (unsealed) item-backup blobs are rejected with `backup.ErrUnsealedBlob` wrapped in `backup.ErrInvalidBlob` (HTTP 400). There is no opt-in to accept them.
- `model.MaxCertificateValidityDays = 36500`.
- The certificate owner comparison in `ValidateKeyOwnership`/`ValidateCertificateAccess` stays (B32 decision); this plan does not widen it.
- Each fixed issue gets a `.claude/known-bugs.md` entry in the structure of § B69, inserted immediately before the line `## Deferred Refactors`. Commits closing an issue carry a `Fixes #N` footer.
- Merge note: `docs/superpowers/plans/2026-09-30-secrets-and-error-responses.md` (B82) also edits `writeCertificateError` in `api/errors_certificate.go`, adding `case errors.Is(err, repositories.ErrNameTaken): c.SetConflict(...)` before `default:` (and the `rocketvault/internal/repositories` import). This plan adds the `ErrSigningKeyForbidden`, `ErrCACertForbidden`, `ErrSigningKeyUnusable`, `ErrSigningKeyNotFound` (Task 9) and `ErrInvalidValidityDays` (Task 10) arms to the same switch. Both are additive arms of one `switch`: whichever plan lands second merges its arms into the existing switch and keeps the other's, and must not replace the switch body wholesale.
- Documentation goes under `.claude/` or `docs/`, never new top-level files.

## Review Focus

1. Pre-upgrade unsealed blobs, including a hand-written forged one, must be refused with 400 and must write nothing.
2. A blob sealed under a previous master key (after `master-key rotate`) must be refused as unauthenticated, not decoded.
3. A deployment whose container forgets to set the seal key must fail closed, and a correctly configured container must seal.
4. A legitimate same-vault restore must keep its key and CA links, or auto-renew silently stops for every restored certificate.
5. Certificate rows with no vault, or whose owner lost `keys/sign`, must be skipped by the scheduler rather than renewed under a broader scope.

Tests pinning each:
1. `TestRestoreCertificate_RejectsLegacyUnsealedBlob`, `TestRestoreKey_RejectsForgedHSMHandle` (Task 2, `internal/backup/item_backup_seal_test.go`) and `TestRestoreCertificateHandler_LegacyUnsealedBlob_Returns400` (Task 2, `api/backup_item_seal_test.go`).
2. `TestRestore_RejectsBlobSealedUnderAnotherMasterKey` (Task 2).
3. `TestItemBackup_FailsClosedWithoutSealKey` (Task 2, `internal/backup/item_backup_seal_test.go`) and `TestItemBackupService_SealedWhenMasterKeyConfigured` (Task 2, `internal/container/item_backup_seal_test.go`).
4. `TestRestoreCertificate_KeepsSameVaultReferences` (Task 3).
5. `TestCheckAndRenewCertificates_NilVaultSkipped` (Task 1) and `TestCheckAndRenewCertificates_RefusesWhenOwnerCannotSign` (Task 8).

---

### Task 1: Auto-renew scheduler renews under the certificate's vault scope (B76)

**Files:**
- Modify: `internal/services/certificates/renewal_service.go:6-13` (imports), `:74-93` (AutoRenew branch)
- Test: `internal/services/certificates/renewal_service_test.go:187-219` (`TestCheckAndRenewCertificates_AutoRenew`), new test appended
- Test: `internal/services/certificates/certificate_service_extended_test.go:1027-1057` (`TestCheckAndRenewCertificates_AutoRenewFailureSkipped`)
- Test: `internal/services/certificates/ca_renewal_scheduler_test.go:21-90`

**Interfaces:**
- Consumes: `model.NewVaultScope(vaultID, actorID uuid.UUID) model.Scope` (`model/scope.go:39`).
- Produces: no new API. Behavior: `CheckAndRenewCertificates` calls `RenewCertificate(ctx, cert.ID, model.NewVaultScope(cert.VaultID, cert.UserID), validityDays)` and skips rows whose `VaultID == uuid.Nil`.

- [ ] **Step 1: Write the failing tests**

In `internal/services/certificates/renewal_service_test.go`, replace the body of `TestCheckAndRenewCertificates_AutoRenew` (lines 187-219) with:

```go
func TestCheckAndRenewCertificates_AutoRenew(t *testing.T) {
	expires := time.Now().Add(10 * 24 * time.Hour)
	certID := uuid.New()
	userID := uuid.New()
	vaultID := uuid.New()
	cert := model.Certificate{
		ID:          certID,
		UserID:      userID,
		VaultID:     vaultID,
		Name:        "test-cert",
		CreatedAt:   time.Now().Add(-365 * 24 * time.Hour),
		ExpiresAt:   &expires,
		AutoRenew:   true,
		RenewalDays: 30,
	}

	repo := &mockCertRepoForRenewal{}
	repo.On("ListAll", mock.Anything).Return([]model.Certificate{cert}, nil)

	// B76: the scheduler must renew inside the certificate's own vault. An
	// admin scope carries no vault predicate, so it let a restored row reach
	// keys and CA certificates in other vaults.
	certSvc := &mockCertSvcForRenewal{}
	certSvc.On("RenewCertificate", mock.Anything, certID, model.NewVaultScope(vaultID, userID), mock.AnythingOfType("int")).
		Return(&certificates.CreateCertificateResult{CertID: uuid.New()}, nil)

	svc := certificates.NewCertificateRenewalService(certificates.RenewalServiceConfig{
		CertRepository:     repo,
		CertificateService: certSvc,
		Logger:             newTestLogger(),
	})

	renewed, warned, err := svc.CheckAndRenewCertificates(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 1, renewed)
	assert.Equal(t, 0, warned)
	certSvc.AssertExpectations(t)
}

// TestCheckAndRenewCertificates_NilVaultSkipped pins that a row with no vault
// is never renewed. There is no vault to scope the renewal to, and falling
// back to a broader scope is the B76 defect.
func TestCheckAndRenewCertificates_NilVaultSkipped(t *testing.T) {
	expires := time.Now().Add(10 * 24 * time.Hour)
	cert := model.Certificate{
		ID:          uuid.New(),
		UserID:      uuid.New(),
		Name:        "no-vault",
		CreatedAt:   time.Now().Add(-365 * 24 * time.Hour),
		ExpiresAt:   &expires,
		AutoRenew:   true,
		RenewalDays: 30,
	}

	repo := &mockCertRepoForRenewal{}
	repo.On("ListAll", mock.Anything).Return([]model.Certificate{cert}, nil)
	certSvc := &mockCertSvcForRenewal{}

	svc := certificates.NewCertificateRenewalService(certificates.RenewalServiceConfig{
		CertRepository:     repo,
		CertificateService: certSvc,
		Logger:             newTestLogger(),
	})

	renewed, warned, err := svc.CheckAndRenewCertificates(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 0, renewed)
	assert.Equal(t, 0, warned)
	certSvc.AssertNotCalled(t, "RenewCertificate", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
}
```

In `internal/services/certificates/certificate_service_extended_test.go`, `TestCheckAndRenewCertificates_AutoRenewFailureSkipped`: after `userID := uuid.New()` add `vaultID := uuid.New()`, add `VaultID:     vaultID,` after `UserID:      userID,` in the certificate literal, and replace

```go
	certSvc.On("RenewCertificate", mock.Anything, certID, model.NewAdminScope(userID), mock.AnythingOfType("int")).
```

with

```go
	certSvc.On("RenewCertificate", mock.Anything, certID, model.NewVaultScope(vaultID, userID), mock.AnythingOfType("int")).
```

In `internal/services/certificates/ca_renewal_scheduler_test.go`:
- after `userID := uuid.New()` (line 24) add `vaultID := uuid.New()`;
- in the `original` literal, change `ID: certID, UserID: userID, KeyID: keyID, CACertID: &caCertID,` to `ID: certID, UserID: userID, VaultID: vaultID, KeyID: keyID, CACertID: &caCertID,`;
- in the `caCert` literal, change `ID: caCertID, UserID: userID, Name: "scheduler-ca",` to `ID: caCertID, UserID: userID, VaultID: vaultID, Name: "scheduler-ca",`;
- replace `adminScope := model.NewAdminScope(userID)` with `vaultScope := model.NewVaultScope(vaultID, userID)` and rename the four later uses of `adminScope` in that function to `vaultScope`.

- [ ] **Step 2: Run the tests and confirm they fail**

Run: `go test ./internal/services/certificates/ -run 'TestCheckAndRenewCertificates' -v`
Expected: FAIL. `TestCheckAndRenewCertificates_AutoRenew`, `_AutoRenewFailureSkipped` and `_NilVaultSkipped` panic with `mock: I don't know what to return because the method call was unexpected` (the scheduler still passes `model.NewAdminScope`), and `TestCheckAndRenewCertificates_CASignedKeepsIssuer` fails the same way on `certRepo.Read`.

- [ ] **Step 3: Implement**

In `internal/services/certificates/renewal_service.go`, add `"github.com/google/uuid"` to the imports:

```go
import (
	"context"
	"time"

	"github.com/google/uuid"

	"rocketvault/internal/logging"
	"rocketvault/internal/repositories"
	"rocketvault/model"
)
```

Replace

```go
		if cert.AutoRenew {
			// Preserve original validity period when renewing.
```

with

```go
		if cert.AutoRenew {
			// A row with no vault cannot be scoped to one, so it is never
			// renewed. Renewing under an admin scope is what let a restored
			// row reach keys and CA certificates in other vaults (B76).
			if cert.VaultID == uuid.Nil {
				s.logger.LogAuditError(cert.UserID.String(), "cert_auto_renew", "failed",
					"Auto-renewal skipped, certificate has no vault: "+cert.Name, nil)
				continue
			}

			// Preserve original validity period when renewing.
```

and replace

```go
			_, err := s.certSvc.RenewCertificate(ctx, cert.ID, model.NewAdminScope(cert.UserID), validityDays)
```

with

```go
			// The renewal is scoped to the certificate's own vault, so its key
			// and CA links are only followed inside that vault (B76).
			_, err := s.certSvc.RenewCertificate(ctx, cert.ID, model.NewVaultScope(cert.VaultID, cert.UserID), validityDays)
```

- [ ] **Step 4: Run the tests and confirm they pass**

Run: `go test ./internal/services/certificates/ -run 'TestCheckAndRenewCertificates' -v`
Expected: PASS.

Run: `go test ./internal/services/certificates/`
Expected: PASS.

- [ ] **Step 5: Commit**

Stage `internal/services/certificates/renewal_service.go`, `internal/services/certificates/renewal_service_test.go`, `internal/services/certificates/certificate_service_extended_test.go`, `internal/services/certificates/ca_renewal_scheduler_test.go`, then invoke the `dev-workflow-skills:1-git-commit` skill via the Skill tool. Subject should say the renewal scheduler now renews under the certificate's vault scope (B76). No `Fixes` footer yet.

---

### Task 2: Seal item-backup blobs under a master-key-derived key (B76)

**Files:**
- Create: `internal/backup/blob_seal.go`
- Modify: `internal/backup/item_backup.go:62-71` (struct), `:143-157` (BackupSecret), `:168-173` (RestoreSecret), `:267-280` (BackupKey), `:284-289` (RestoreKey), `:360-366` (BackupCertificate), `:371-375` (RestoreCertificate)
- Modify: `internal/backup/export_test.go`
- Modify: `internal/container/service_container.go:6-40` (imports), `:729-742` (item backup wiring)
- Modify: `.claude/azure-keyvault-parity.md:51`, `:223`
- Create: `internal/backup/seal_helpers_test.go`, `internal/backup/item_backup_seal_test.go`, `api/backup_item_seal_test.go`, `internal/container/item_backup_seal_test.go`
- Modify (mechanical): `internal/backup/item_backup_test.go`, `internal/backup/backup_edge_test.go`, `internal/backup/item_backup_atomicity_test.go`, `api/backup_item_test.go`

**Interfaces:**
- Consumes: `common.EncryptWithKey(value string, key []byte) (string, error)`, `common.DecryptWithKey(encryptedValue string, key []byte) (string, error)`, `common.ParseMasterKey(encoded string) ([]byte, error)` (`common/encrypt.go`); `crypto/hkdf.Key`.
- Produces:
  - `func (s *ItemBackupService) SetSealKey(masterKey []byte) error`
  - `var ErrSealKeyUnset, ErrUnsealedBlob, ErrBlobAuthentication error` in package `backup`
  - unexported `(s *ItemBackupService) sealBlob(inner string) (string, error)`, `openBlob(blob string) (string, error)`, const `sealedBlobPrefix = "rvb2."`
  - test-only: `ExportedSealedBlobPrefix`, `(*ItemBackupService).ExportedSealBlob(inner string) (string, error)`, `(*ItemBackupService).ExportedOpenBlob(blob string) (string, error)`; `newTestItemBackupService(...)` in `backup_test`; `newSealedItemBackupService(...)` in `api` tests.

- [ ] **Step 1: Add the test helpers and the test-only exports**

Create `internal/backup/seal_helpers_test.go`:

```go
package backup_test

import (
	"bytes"

	"rocketvault/internal/backup"
	"rocketvault/internal/repositories"
)

// testMasterKey is a fixed 32-byte master key used only by tests.
var testMasterKey = bytes.Repeat([]byte{0x42}, 32)

// newTestItemBackupService builds an ItemBackupService with its seal key set,
// so tests exercise the sealed blob format production uses.
func newTestItemBackupService(
	secretRepo repositories.SecretRepositoryInterface,
	keyRepo repositories.KeyRepositoryInterface,
	certRepo repositories.CertificateRepositoryInterface,
	versionRepo repositories.SecretVersionRepositoryInterface,
) *backup.ItemBackupService {
	svc := backup.NewItemBackupService(secretRepo, keyRepo, certRepo, versionRepo)
	if err := svc.SetSealKey(testMasterKey); err != nil {
		panic(err)
	}
	return svc
}
```

Replace the whole of `internal/backup/export_test.go` with:

```go
package backup

// Test-only aliases. This file is compiled only under `go test`, so these
// export nothing to production consumers.

type ExportedBlobVersions = blobVersions

var (
	ExportedEncodeBlob = encodeBlob
	ExportedDecodeBlob = decodeBlob
)

// ExportedSealedBlobPrefix is the sealed-format marker, for format tests.
const ExportedSealedBlobPrefix = sealedBlobPrefix

// ExportedSealBlob seals a hand-built inner envelope, so a test can check
// that an older inner shape still restores once it is sealed.
func (s *ItemBackupService) ExportedSealBlob(inner string) (string, error) {
	return s.sealBlob(inner)
}

// ExportedOpenBlob unseals a blob this service produced and returns its inner
// envelope, so a test can decode what BackupSecret, BackupKey or
// BackupCertificate returned. Those now return sealed blobs, which
// ExportedDecodeBlob alone cannot read.
func (s *ItemBackupService) ExportedOpenBlob(blob string) (string, error) {
	return s.openBlob(blob)
}
```

Create `api/backup_item_seal_test.go`:

```go
package api

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"

	"rocketvault/internal/backup"
	"rocketvault/internal/repositories"
	"rocketvault/model"
)

// apiTestSealKey is a fixed 32-byte master key used only by tests.
var apiTestSealKey = bytes.Repeat([]byte{0x42}, 32)

// newSealedItemBackupService builds an ItemBackupService with its seal key
// set, as the real container does.
func newSealedItemBackupService(
	secretRepo repositories.SecretRepositoryInterface,
	keyRepo repositories.KeyRepositoryInterface,
	certRepo repositories.CertificateRepositoryInterface,
	versionRepo repositories.SecretVersionRepositoryInterface,
) *backup.ItemBackupService {
	svc := backup.NewItemBackupService(secretRepo, keyRepo, certRepo, versionRepo)
	if err := svc.SetSealKey(apiTestSealKey); err != nil {
		panic(err)
	}
	return svc
}

// TestRestoreCertificateHandler_LegacyUnsealedBlob_Returns400 pins B76 on the
// HTTP path. A hand-written blob in the old base64url format names a key in
// another vault; it must be refused as a bad parameter and write nothing.
func TestRestoreCertificateHandler_LegacyUnsealedBlob_Returns400(t *testing.T) {
	raw, err := json.Marshal(map[string]any{
		"resource_type": "certificate",
		"resource_id":   uuid.New().String(),
		"data":          map[string]any{"name": "forged", "key_id": uuid.New().String(), "auto_renew": true},
	})
	if err != nil {
		t.Fatal(err)
	}
	legacy := base64.URLEncoding.EncodeToString(raw)

	created := false
	certRepo := &mockCertRepo{
		createFn: func(_ context.Context, _ *model.Certificate) error {
			created = true
			return nil
		},
	}
	c := newBackupCtxWithCert(certRepo)
	w := httptest.NewRecorder()
	body, _ := json.Marshal(map[string]string{"blob": legacy})
	r := httptest.NewRequest(http.MethodPost, "/certificates/restore", bytes.NewReader(body))

	restoreCertificateHandler(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.False(t, created, "a rejected blob must not reach the repository")
}
```

Run the mechanical swap so every existing test uses a sealed service:

```bash
sed -i 's/backup\.NewItemBackupService(/newTestItemBackupService(/g' \
  internal/backup/item_backup_test.go \
  internal/backup/backup_edge_test.go \
  internal/backup/item_backup_atomicity_test.go
sed -i 's/backup\.NewItemBackupService(/newSealedItemBackupService(/g' api/backup_item_test.go
```

Then remove the now-unused `"rocketvault/internal/backup"` import line from `internal/backup/item_backup_atomicity_test.go` (it uses no other `backup.` identifier). `internal/backup/backup_edge_test.go` and `internal/backup/item_backup_test.go` keep the import (they still use `backup.ErrInvalidBlob` and `backup.ExportedDecodeBlob`), and `api/backup_item_test.go` keeps it for `*backup.ItemBackupService`. The sed also rewrites the `buildValid*Blob` helpers in `api/backup_item_test.go`, so every handler-test blob is sealed.

Every other existing test is unaffected by the format change, verified by reading them:
- `TestBlobEnvelope_SecretVersionsRoundTrip` and `TestBlobEnvelope_KeyVersionsUnaffected` call `ExportedEncodeBlob` and `ExportedDecodeBlob` directly on the unsealed inner envelope, so they never see a sealed blob.
- The restore tests in `backup_edge_test.go` and `item_backup_atomicity_test.go` pass blobs between services that are all built through `newTestItemBackupService`, so they share one seal key. `TestRestoreKeyBlobError` and `TestRestoreCertificateBlobError` (`"!!!not-base64!!!"`, `"!!!bad!!!"`) now fail in `openBlob` with `ErrUnsealedBlob` wrapped in `ErrInvalidBlob`, which still satisfies their `errors.Is(err, backup.ErrInvalidBlob)` assertion.
- The API handler tests with `badBlob := "dGhpcyBpcyBub3QgYW4gZW52ZWxvcGU="` still get 400 for the same reason.

The one other test that decodes the output of a `Backup*` call is `TestBackupSecret_CarriesVersionHistory` in `internal/backup/item_backup_test.go`. Its `backup.ExportedDecodeBlob(blob, "secret", &restored)` now receives an `rvb2.`-sealed blob and would fail with `illegal base64 data`. Replace

```go
	var restored model.Secret
	got, err := backup.ExportedDecodeBlob(blob, "secret", &restored)
	require.NoError(t, err)
	require.Len(t, got.Secret, 2, "both archived versions must reach the blob")
```

with

```go
	inner, err := svc.ExportedOpenBlob(blob)
	require.NoError(t, err)

	var restored model.Secret
	got, err := backup.ExportedDecodeBlob(inner, "secret", &restored)
	require.NoError(t, err)
	require.Len(t, got.Secret, 2, "both archived versions must reach the blob")
```

(`svc` there is already the `newTestItemBackupService` result after the sed.)

In `internal/backup/item_backup_test.go`, `TestRestoreSecret_OldFormatBlob_NoVersionsField`, replace

```go
	blob := base64.URLEncoding.EncodeToString(raw)

	repo := newStubSecretRepo()
	vr := newStubSecretVersionRepo()
	svc := newTestItemBackupService(repo, nil, nil, vr)
```

with

```go
	repo := newStubSecretRepo()
	vr := newStubSecretVersionRepo()
	svc := newTestItemBackupService(repo, nil, nil, vr)

	// The inner envelope keeps its pre-versions shape. Only the outer seal is
	// new, and every blob this server hands out now carries it.
	blob, err := svc.ExportedSealBlob(base64.URLEncoding.EncodeToString(raw))
	require.NoError(t, err)
```

- [ ] **Step 2: Write the failing service tests**

Create `internal/backup/item_backup_seal_test.go`:

```go
package backup_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"rocketvault/internal/backup"
	"rocketvault/model"
)

// legacyBlob hand-builds a blob in the pre-sealing format: a bare base64url
// JSON envelope, which anyone can write.
func legacyBlob(t *testing.T, resourceType string, data any) string {
	t.Helper()
	raw, err := json.Marshal(data)
	require.NoError(t, err)
	env, err := json.Marshal(map[string]any{
		"resource_type": resourceType,
		"resource_id":   uuid.New().String(),
		"data":          json.RawMessage(raw),
	})
	require.NoError(t, err)
	return base64.URLEncoding.EncodeToString(env)
}

func TestBackupBlob_IsSealed(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	owner, vaultID := uuid.New(), uuid.New()
	repo := newStubCertRepo()
	cert := &model.Certificate{ID: uuid.New(), UserID: owner, VaultID: vaultID, Name: "sealed-cert"}
	require.NoError(t, repo.Create(ctx, cert))
	svc := newTestItemBackupService(nil, nil, repo, nil)

	blob, err := svc.BackupCertificate(ctx, cert.ID, owner, vaultID)
	require.NoError(t, err)
	assert.True(t, strings.HasPrefix(blob, backup.ExportedSealedBlobPrefix),
		"a new blob must carry the sealed-format marker")
	_, decodeErr := base64.URLEncoding.DecodeString(blob)
	assert.Error(t, decodeErr, "a sealed blob must not be a bare base64url envelope")
}

// TestRestoreCertificate_RejectsLegacyUnsealedBlob is the B76 regression: a
// forged blob naming a key in another vault must be refused outright.
func TestRestoreCertificate_RejectsLegacyUnsealedBlob(t *testing.T) {
	t.Parallel()

	blob := legacyBlob(t, "certificate", &model.Certificate{
		ID: uuid.New(), Name: "forged", KeyID: uuid.New(), AutoRenew: true,
	})
	repo := newStubCertRepo()
	svc := newTestItemBackupService(nil, nil, repo, nil)

	err := svc.RestoreCertificate(context.Background(), blob, uuid.New(), uuid.New(), uuid.New())
	require.ErrorIs(t, err, backup.ErrInvalidBlob)
	require.ErrorIs(t, err, backup.ErrUnsealedBlob)
	assert.Empty(t, repo.certs, "a rejected blob must write nothing")
}

// TestRestoreKey_RejectsForgedHSMHandle pins the HSM half of B76: an HSM key
// blob stores a pkcs11 handle, so a forged blob could bind a new key row to
// any HSM object. Sealing makes that blob unrestorable.
func TestRestoreKey_RejectsForgedHSMHandle(t *testing.T) {
	t.Parallel()

	blob := legacyBlob(t, "key", &model.Key{
		ID: uuid.New(), Name: "hijack", Type: model.KeyTypeRSA,
		Value: "pkcs11:victim-vault-key", Enabled: true,
	})
	repo := newStubKeyRepo()
	svc := newTestItemBackupService(nil, repo, nil, nil)

	err := svc.RestoreKey(context.Background(), blob, uuid.New(), uuid.New(), uuid.New())
	require.ErrorIs(t, err, backup.ErrUnsealedBlob)
	assert.Empty(t, repo.keys, "a rejected blob must write nothing")
}

func TestRestore_RejectsTamperedBlob(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	owner, vaultID, secretID := uuid.New(), uuid.New(), uuid.New()
	repo := newStubSecretRepo()
	require.NoError(t, repo.Create(ctx, &model.Secret{
		ID: secretID, UserID: owner, VaultID: vaultID, Name: "s", Value: "v", Version: 1, Enabled: true,
	}))
	svc := newTestItemBackupService(repo, nil, nil, newStubSecretVersionRepo())

	blob, err := svc.BackupSecret(ctx, secretID, owner, vaultID)
	require.NoError(t, err)

	raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(blob, backup.ExportedSealedBlobPrefix))
	require.NoError(t, err)
	raw[len(raw)-1] ^= 0x01
	tampered := backup.ExportedSealedBlobPrefix + base64.StdEncoding.EncodeToString(raw)

	err = svc.RestoreSecret(ctx, tampered, owner, vaultID, uuid.New())
	require.ErrorIs(t, err, backup.ErrInvalidBlob)
	require.ErrorIs(t, err, backup.ErrBlobAuthentication)
}

// TestRestore_RejectsBlobSealedUnderAnotherMasterKey covers blobs taken
// before a master-key rotation. Their inner values are ciphertext under the
// old key anyway, so refusing them loses nothing that ever worked.
func TestRestore_RejectsBlobSealedUnderAnotherMasterKey(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	owner, vaultID, secretID := uuid.New(), uuid.New(), uuid.New()
	repo := newStubSecretRepo()
	require.NoError(t, repo.Create(ctx, &model.Secret{
		ID: secretID, UserID: owner, VaultID: vaultID, Name: "s", Value: "v", Version: 1, Enabled: true,
	}))
	svc := newTestItemBackupService(repo, nil, nil, newStubSecretVersionRepo())
	blob, err := svc.BackupSecret(ctx, secretID, owner, vaultID)
	require.NoError(t, err)

	other := backup.NewItemBackupService(repo, nil, nil, newStubSecretVersionRepo())
	require.NoError(t, other.SetSealKey(bytes.Repeat([]byte{0x43}, 32)))

	err = other.RestoreSecret(ctx, blob, owner, vaultID, uuid.New())
	require.ErrorIs(t, err, backup.ErrBlobAuthentication)
}

func TestItemBackup_FailsClosedWithoutSealKey(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	owner, vaultID, secretID := uuid.New(), uuid.New(), uuid.New()
	repo := newStubSecretRepo()
	require.NoError(t, repo.Create(ctx, &model.Secret{
		ID: secretID, UserID: owner, VaultID: vaultID, Name: "s", Value: "v", Version: 1, Enabled: true,
	}))
	svc := backup.NewItemBackupService(repo, nil, nil, newStubSecretVersionRepo())

	_, err := svc.BackupSecret(ctx, secretID, owner, vaultID)
	require.ErrorIs(t, err, backup.ErrSealKeyUnset)

	err = svc.RestoreSecret(ctx, "rvb2.anything", owner, vaultID, uuid.New())
	require.ErrorIs(t, err, backup.ErrSealKeyUnset)
}

func TestSetSealKey_RejectsWrongLength(t *testing.T) {
	t.Parallel()

	svc := backup.NewItemBackupService(nil, nil, nil, nil)
	require.Error(t, svc.SetSealKey(make([]byte, 16)))
}
```

- [ ] **Step 3: Run the tests and confirm they fail**

Run: `go test ./internal/backup/ ./api/ -run 'Seal|Legacy|Tampered|ForgedHSM|AnotherMasterKey|OldFormat' -v`
Expected: FAIL at build time with `svc.SetSealKey undefined`, `undefined: sealedBlobPrefix`, `undefined: backup.ErrUnsealedBlob` and similar.

- [ ] **Step 4: Implement the seal**

Create `internal/backup/blob_seal.go`:

```go
package backup

import (
	"crypto/hkdf"
	"crypto/sha256"
	"errors"
	"fmt"
	"strings"

	"rocketvault/common"
)

// sealedBlobPrefix marks a blob sealed under the item-backup key. It is also
// the format version: a blob without it predates sealing and is refused.
const sealedBlobPrefix = "rvb2."

// sealKeyInfo is the HKDF info string. It keeps the item-backup key distinct
// from the master key itself and from any other key derived from it.
const sealKeyInfo = "rocketvault item-backup blob seal v2"

// sealKeySize is the AES-256 key length in bytes.
const sealKeySize = 32

var (
	// ErrSealKeyUnset is returned when backup or restore runs before
	// SetSealKey. Backup and restore fail closed rather than fall back to the
	// unauthenticated format.
	ErrSealKeyUnset = errors.New("item backup seal key is not configured")

	// ErrUnsealedBlob marks a blob in the pre-sealing format. Such a blob was
	// either taken before the upgrade or written by hand, and the two cannot
	// be told apart, so both are refused.
	ErrUnsealedBlob = errors.New("blob is not sealed; take a new backup with this server")

	// ErrBlobAuthentication marks a sealed blob that failed its integrity
	// check: it was modified, or sealed under a different master key.
	ErrBlobAuthentication = errors.New("blob failed authentication")
)

// SetSealKey derives the blob-sealing key from the raw 32-byte master key.
// Every blob is then encrypted and authenticated, so restore accepts only
// blobs this server produced, unmodified (B76).
func (s *ItemBackupService) SetSealKey(masterKey []byte) error {
	if len(masterKey) != sealKeySize {
		return fmt.Errorf("item backup seal key: master key must be %d bytes, got %d", sealKeySize, len(masterKey))
	}
	key, err := hkdf.Key(sha256.New, masterKey, nil, sealKeyInfo, sealKeySize)
	if err != nil {
		return fmt.Errorf("item backup seal key: derive: %w", err)
	}
	s.sealKey = key
	return nil
}

// sealBlob encrypts and authenticates an encoded envelope with AES-256-GCM.
func (s *ItemBackupService) sealBlob(inner string) (string, error) {
	if s.sealKey == nil {
		return "", ErrSealKeyUnset
	}
	sealed, err := common.EncryptWithKey(inner, s.sealKey)
	if err != nil {
		return "", fmt.Errorf("seal backup blob: %w", err)
	}
	return sealedBlobPrefix + sealed, nil
}

// openBlob reverses sealBlob. Both refusals wrap ErrInvalidBlob, so the HTTP
// handlers report them as a bad parameter rather than a server fault.
func (s *ItemBackupService) openBlob(blob string) (string, error) {
	if s.sealKey == nil {
		return "", ErrSealKeyUnset
	}
	body, ok := strings.CutPrefix(blob, sealedBlobPrefix)
	if !ok {
		return "", fmt.Errorf("%w: %w", ErrInvalidBlob, ErrUnsealedBlob)
	}
	inner, err := common.DecryptWithKey(body, s.sealKey)
	if err != nil {
		return "", fmt.Errorf("%w: %w", ErrInvalidBlob, ErrBlobAuthentication)
	}
	return inner, nil
}
```

In `internal/backup/item_backup.go`, replace the struct doc and struct (lines 62-71) with:

```go
// ItemBackupService provides per-item backup and restore for secrets, keys,
// and certificates. Each backup is a JSON envelope, encrypted and
// authenticated under a key derived from the master key (see blob_seal.go),
// and is opaque to the caller.
type ItemBackupService struct {
	secretRepo  repositories.SecretRepositoryInterface
	keyRepo     repositories.KeyRepositoryInterface
	certRepo    repositories.CertificateRepositoryInterface
	versionRepo repositories.SecretVersionRepositoryInterface
	txBeginner  TxBeginner
	// sealKey is set by SetSealKey. While it is nil, backup and restore fail
	// with ErrSealKeyUnset.
	sealKey []byte
}
```

In `BackupSecret`, replace `return encodeBlob("secret", id.String(), secret, blobVersions{Secret: versions})` with:

```go
	inner, err := encodeBlob("secret", id.String(), secret, blobVersions{Secret: versions})
	if err != nil {
		return "", err
	}
	return s.sealBlob(inner)
```

In `BackupKey`, replace `return encodeBlob("key", id.String(), key, blobVersions{Key: versions})` with:

```go
	inner, err := encodeBlob("key", id.String(), key, blobVersions{Key: versions})
	if err != nil {
		return "", err
	}
	return s.sealBlob(inner)
```

In `BackupCertificate`, replace `return encodeBlob("certificate", id.String(), cert, blobVersions{})` with:

```go
	inner, err := encodeBlob("certificate", id.String(), cert, blobVersions{})
	if err != nil {
		return "", err
	}
	return s.sealBlob(inner)
```

In `RestoreSecret`, replace

```go
	var secret model.Secret
	versions, err := decodeBlob(blob, "secret", &secret)
```

with

```go
	inner, err := s.openBlob(blob)
	if err != nil {
		return err
	}
	var secret model.Secret
	versions, err := decodeBlob(inner, "secret", &secret)
```

In `RestoreKey`, replace

```go
	var key model.Key
	versions, err := decodeBlob(blob, "key", &key)
```

with

```go
	inner, err := s.openBlob(blob)
	if err != nil {
		return err
	}
	var key model.Key
	versions, err := decodeBlob(inner, "key", &key)
```

In `RestoreCertificate`, replace

```go
	var cert model.Certificate
	if _, err := decodeBlob(blob, "certificate", &cert); err != nil {
		return err
	}
```

with

```go
	inner, err := s.openBlob(blob)
	if err != nil {
		return err
	}
	var cert model.Certificate
	if _, err := decodeBlob(inner, "certificate", &cert); err != nil {
		return err
	}
```

- [ ] **Step 5: Run the service and handler tests and confirm they pass**

Run: `go test ./internal/backup/ ./api/ -v -run 'Seal|Legacy|Tampered|ForgedHSM|AnotherMasterKey|OldFormat|Backup|Restore'`
Expected: PASS.

Run: `go test ./internal/backup/ ./api/`
Expected: PASS.

- [ ] **Step 6: Write the failing container wiring test**

Create `internal/container/item_backup_seal_test.go`:

```go
package container

import (
	"bytes"
	"context"
	"encoding/base64"
	"testing"

	"github.com/google/uuid"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"

	"rocketvault/internal/backup"
)

// TestItemBackupService_SealedWhenMasterKeyConfigured pins the container
// wiring for B76. Only a service with its seal key set reports an unsealed
// blob as unsealed; an unwired one reports ErrSealKeyUnset instead.
func TestItemBackupService_SealedWhenMasterKeyConfigured(t *testing.T) {
	orig := viper.GetString("master_key")
	t.Cleanup(func() { viper.Set("master_key", orig) })
	viper.Set("master_key", base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x24}, 32)))

	// newMinimalConfig supplies the database and cache settings a real
	// container needs, so GetItemBackupService cannot return nil here.
	c, err := NewServiceContainer(newMinimalConfig(t))
	require.NoError(t, err)
	t.Cleanup(func() { _ = c.Close() })

	err = c.GetItemBackupService().RestoreSecret(context.Background(), "not-a-sealed-blob", uuid.New(), uuid.New(), uuid.New())
	require.ErrorIs(t, err, backup.ErrUnsealedBlob)
}
```

Run: `go test ./internal/container/ -run TestItemBackupService_SealedWhenMasterKeyConfigured -v`
Expected: FAIL, the error is `item backup seal key is not configured`, not `ErrUnsealedBlob`.

- [ ] **Step 7: Wire the seal key in the container**

In `internal/container/service_container.go`, add `"rocketvault/common"` to the import block (it is not imported today). Then replace

```go
	c.itemBackupService.SetTxBeginner(c.conn)

	return nil
}
```

with

```go
	c.itemBackupService.SetTxBeginner(c.conn)
	// Seals every item-backup blob under a key derived from the master key,
	// so a forged or edited blob is refused at restore (B76). A missing or
	// malformed master key leaves the service unsealed, and backup and
	// restore then fail closed instead of using the unauthenticated format.
	// bootstrap.ValidateMasterKey already aborts startup on a bad key.
	if masterKey, keyErr := common.ParseMasterKey(viper.GetString("master_key")); keyErr != nil {
		c.logger.WithError(keyErr).Warn("master key unavailable, item backup and restore are disabled")
	} else if err := c.itemBackupService.SetSealKey(masterKey); err != nil {
		return fmt.Errorf("failed to configure item backup sealing: %w", err)
	}

	return nil
}
```

Run: `go test ./internal/container/ -run TestItemBackupService_SealedWhenMasterKeyConfigured -v`
Expected: PASS.

- [ ] **Step 8: Update the parity doc**

In `.claude/azure-keyvault-parity.md` line 223, replace

`note this is an unencrypted, same-instance base64url blob (`internal/backup/item_backup.go:360-366`), not a portable export`

with

`the blob is AES-256-GCM sealed under a key derived from the master key (`internal/backup/blob_seal.go`, B76), so it restores only on an instance with the same master key and a modified blob is refused; it is not a portable export`

On line 51, after `or a bare `pkcs11:` handle — never plaintext PEM.` insert ` Since B76 that value additionally sits inside the sealed blob envelope, so a forged `pkcs11:` handle cannot be restored.`

- [ ] **Step 9: Run the full affected packages**

Run: `go build ./... && go vet ./internal/backup/ ./internal/container/ ./api/ && go test ./internal/backup/ ./internal/container/ ./api/`
Expected: PASS.

- [ ] **Step 10: Commit**

Stage the created and modified files of this task, then invoke the `dev-workflow-skills:1-git-commit` skill via the Skill tool. Subject should say item-backup blobs are now sealed under a master-key-derived key and unsealed blobs are refused (B76). No `Fixes` footer yet.

---

### Task 3: Restore drops key and CA links that do not resolve in the target vault (B76)

**Files:**
- Modify: `internal/backup/item_backup.go` (`RestoreCertificate` after the ID/UserID/VaultID assignments; new method `dropForeignReferences` after `restoreCertificateWith`)
- Create: `internal/backup/item_backup_cert_refs_test.go`
- Modify: `.claude/known-bugs.md` (new § B76 before `## Deferred Refactors`)

**Interfaces:**
- Consumes: `ItemBackupService.openBlob` (Task 2); `repositories.KeyRepositoryInterface.Read(ctx, id, scope) (*model.Key, error)`; `repositories.CertificateRepositoryInterface.Read(ctx, id, scope) (*model.Certificate, error)`.
- Produces: unexported `(s *ItemBackupService) dropForeignReferences(ctx context.Context, cert *model.Certificate, userID, vaultID uuid.UUID)`. Behavior: a restored certificate keeps `KeyID`/`CACertID` only when each reads successfully under `model.NewVaultScope(vaultID, userID)`.

Decision recorded here and in § B76: clear, do not reject. Restoring a backup into a different vault is a supported operation (B15), and the certificate body and private key the row carries are valid there; only its links point at objects the restoring caller was never authorized for. A cleared `KeyID` makes renewal refuse (`certificate has no associated key ID`), a cleared `CACertID` makes renewal refuse (`signed by a CA this installation no longer records`), and Task 6 refuses a cleared CA as a signer. Every consequence of clearing is a refusal, never a wider grant. `RestoreSecret` and `RestoreKey` have no cross-object links, so they need no counterpart; `RestoreKey`'s HSM handle is closed by the seal (Task 2).

- [ ] **Step 1: Write the failing tests**

Create `internal/backup/item_backup_cert_refs_test.go`:

```go
package backup_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"rocketvault/internal/backup"
	"rocketvault/model"
)

// vaultCheckingKeyRepo applies the vault predicate the real KeyRepository
// applies in SQL, which stubKeyRepo deliberately ignores.
type vaultCheckingKeyRepo struct{ *stubKeyRepo }

func (r vaultCheckingKeyRepo) Read(ctx context.Context, id uuid.UUID, scope model.Scope) (*model.Key, error) {
	k, err := r.stubKeyRepo.Read(ctx, id, scope)
	if err != nil {
		return nil, err
	}
	if scope.Kind() != model.ScopeVault || k.VaultID != scope.VaultID() {
		return nil, fmt.Errorf("key not found or access denied")
	}
	return k, nil
}

// vaultCheckingCertRepo is vaultCheckingKeyRepo's certificate twin.
type vaultCheckingCertRepo struct{ *stubCertRepo }

func (r vaultCheckingCertRepo) Read(ctx context.Context, id uuid.UUID, scope model.Scope) (*model.Certificate, error) {
	c, err := r.stubCertRepo.Read(ctx, id, scope)
	if err != nil {
		return nil, err
	}
	if scope.Kind() != model.ScopeVault || c.VaultID != scope.VaultID() {
		return nil, fmt.Errorf("certificate not found or access denied")
	}
	return c, nil
}

// certRefFixture holds, in vault A, a signing key, a CA certificate and a
// leaf certificate linked to both, plus a sealed backup of the leaf.
type certRefFixture struct {
	keys     *stubKeyRepo
	certs    *stubCertRepo
	svc      *backup.ItemBackupService
	owner    uuid.UUID
	vaultA   uuid.UUID
	keyID    uuid.UUID
	caCertID uuid.UUID
	blob     string
}

func newCertRefFixture(t *testing.T) *certRefFixture {
	t.Helper()
	ctx := context.Background()
	owner, vaultA := uuid.New(), uuid.New()
	keyID, caCertID, leafID := uuid.New(), uuid.New(), uuid.New()

	keys := newStubKeyRepo()
	require.NoError(t, keys.Create(ctx, &model.Key{
		ID: keyID, UserID: owner, VaultID: vaultA, Name: "k", Value: "enc", Type: model.KeyTypeRSA, Enabled: true,
	}))
	certs := newStubCertRepo()
	require.NoError(t, certs.Create(ctx, &model.Certificate{ID: caCertID, UserID: owner, VaultID: vaultA, Name: "ca"}))
	require.NoError(t, certs.Create(ctx, &model.Certificate{
		ID: leafID, UserID: owner, VaultID: vaultA, Name: "leaf",
		KeyID: keyID, CACertID: &caCertID, AutoRenew: true,
	}))

	svc := newTestItemBackupService(nil, vaultCheckingKeyRepo{keys}, vaultCheckingCertRepo{certs}, nil)
	blob, err := svc.BackupCertificate(ctx, leafID, owner, vaultA)
	require.NoError(t, err)

	return &certRefFixture{
		keys: keys, certs: certs, svc: svc, owner: owner, vaultA: vaultA,
		keyID: keyID, caCertID: caCertID, blob: blob,
	}
}

// TestRestoreCertificate_DropsCrossVaultReferences is the B76 regression for
// a genuine blob restored into another vault: its links must not survive,
// or the scheduler would later follow them out of the restore vault.
func TestRestoreCertificate_DropsCrossVaultReferences(t *testing.T) {
	t.Parallel()

	f := newCertRefFixture(t)
	vaultB, newID := uuid.New(), uuid.New()
	require.NoError(t, f.svc.RestoreCertificate(context.Background(), f.blob, f.owner, vaultB, newID))

	restored := f.certs.certs[newID]
	require.NotNil(t, restored)
	assert.Equal(t, vaultB, restored.VaultID)
	assert.Equal(t, uuid.Nil, restored.KeyID, "a key in another vault must not stay linked")
	assert.Nil(t, restored.CACertID, "a CA certificate in another vault must not stay linked")
}

// TestRestoreCertificate_KeepsSameVaultReferences guards the common case: a
// restore into the vault the backup came from must keep auto-renew working.
func TestRestoreCertificate_KeepsSameVaultReferences(t *testing.T) {
	t.Parallel()

	f := newCertRefFixture(t)
	newID := uuid.New()
	require.NoError(t, f.svc.RestoreCertificate(context.Background(), f.blob, f.owner, f.vaultA, newID))

	restored := f.certs.certs[newID]
	require.NotNil(t, restored)
	assert.Equal(t, f.keyID, restored.KeyID)
	require.NotNil(t, restored.CACertID)
	assert.Equal(t, f.caCertID, *restored.CACertID)
}

// TestRestoreCertificate_NoKeyRepoDropsKeyReference pins the fail-closed
// branch: a link that cannot be checked is not kept.
func TestRestoreCertificate_NoKeyRepoDropsKeyReference(t *testing.T) {
	t.Parallel()

	f := newCertRefFixture(t)
	svc := newTestItemBackupService(nil, nil, vaultCheckingCertRepo{f.certs}, nil)
	newID := uuid.New()
	require.NoError(t, svc.RestoreCertificate(context.Background(), f.blob, f.owner, f.vaultA, newID))

	restored := f.certs.certs[newID]
	require.NotNil(t, restored)
	assert.Equal(t, uuid.Nil, restored.KeyID)
	require.NotNil(t, restored.CACertID, "the CA link still resolves and is kept")
}
```

- [ ] **Step 2: Run the tests and confirm they fail**

Run: `go test ./internal/backup/ -run 'TestRestoreCertificate_(DropsCrossVault|KeepsSameVault|NoKeyRepo)' -v`
Expected: FAIL. `DropsCrossVaultReferences` reports the key ID and CA ID survived; `NoKeyRepoDropsKeyReference` reports the key ID survived. `KeepsSameVaultReferences` passes already (it is the guard against over-clearing).

- [ ] **Step 3: Implement**

In `internal/backup/item_backup.go`, `RestoreCertificate`, replace

```go
	cert.ID = newID
	cert.UserID = userID
	cert.VaultID = vaultID

	if txCertRepo, repoOK := s.certRepo.(txCapableCertRepo); repoOK && s.txBeginner != nil {
```

with

```go
	cert.ID = newID
	cert.UserID = userID
	cert.VaultID = vaultID
	s.dropForeignReferences(ctx, &cert, userID, vaultID)

	if txCertRepo, repoOK := s.certRepo.(txCapableCertRepo); repoOK && s.txBeginner != nil {
```

After `restoreCertificateWith` (before `// encodeBlob marshals data ...`), add:

```go
// dropForeignReferences clears the certificate's signing-key and CA links
// unless each resolves inside vaultID. A backup may be restored into a vault
// other than the one it came from (B15), and its links then name objects the
// restoring caller was never authorized for. Renewal follows those links, so
// a link that does not resolve here is dropped rather than kept (B76).
//
// Dropping only ever causes a refusal later: renewal refuses a certificate
// with no key, and refuses to re-sign one whose CA it no longer records. Any
// read error counts as "does not resolve", since keeping an unverified link
// is the one outcome this method exists to prevent.
func (s *ItemBackupService) dropForeignReferences(ctx context.Context, cert *model.Certificate, userID, vaultID uuid.UUID) {
	scope := model.NewVaultScope(vaultID, userID)

	if cert.KeyID != uuid.Nil {
		if s.keyRepo == nil {
			cert.KeyID = uuid.Nil
		} else if _, err := s.keyRepo.Read(ctx, cert.KeyID, scope); err != nil {
			cert.KeyID = uuid.Nil
		}
	}

	if cert.CACertID != nil {
		if _, err := s.certRepo.Read(ctx, *cert.CACertID, scope); err != nil {
			cert.CACertID = nil
		}
	}
}
```

- [ ] **Step 4: Run the tests and confirm they pass**

Run: `go test ./internal/backup/ ./api/`
Expected: PASS.

- [ ] **Step 5: File the GitHub issue and add the known-bugs entry**

Create the issue (the convention in `.claude/known-bugs.md` lines 6-12):

```bash
gh issue create --label bug \
  --title "B76: Forged certificate restore blob planted cross-vault key and CA links that auto-renew followed with an admin scope" \
  --body "$(cat <<'EOF'
**Severity**: High

**Files**: `internal/backup/item_backup.go` (RestoreCertificate, encodeBlob/decodeBlob), `internal/repositories/certificate_repository.go` (insertCertAndTags, Update), `internal/services/certificates/renewal_service.go:86`, `internal/repositories/scope_predicate.go`

**Symptom**: A caller with `certificates/restore` in vault B could restore a certificate whose `key_id` and `ca_cert_id` name a key and CA certificate in vault A. The blob was unauthenticated base64url JSON, so the links could also be written by hand. The auto-renew scheduler renewed that row with `model.NewAdminScope(cert.UserID)`, whose predicate is `1 = 1`, so the renewal read the vault-A key and CA, copied the key's private PEM into the vault-B row, and could leave a working CA in vault B signed with a vault-A key. Only the owner comparison stood in the way, and it matches whenever the restorer owns the vault-A objects, including after losing access to vault A. The same blob format let a forged key blob bind a new key row to any `pkcs11:<label>` HSM handle.

**Root cause**: `RestoreCertificate` overwrote only `ID`, `UserID` and `VaultID`; `key_id` and `ca_cert_id` came from the blob and were inserted verbatim (`Update` never rewrites `ca_cert_id`, by design, B37). The blob had no integrity protection. The scheduler used an admin scope, so the B32 vault predicate never applied on the renewal path.

Full detail: .claude/known-bugs.md § B76
EOF
)"
```

Note the issue number the command prints; it is `<N>` below and in the commit footer.

In `.claude/known-bugs.md`, insert immediately before the line `## Deferred Refactors`:

```markdown
### B76 — A forged certificate restore blob planted cross-vault key and CA links that auto-renew followed with an admin scope

**Status**: Fixed 2026-09-30 (GitHub issue #<N>)
**Severity**: High — key material from a vault the caller could not reach
ended up in a row in a vault they could, usable there as a CA signing key
**Files**: `internal/backup/item_backup.go`, `internal/backup/blob_seal.go`
(new), `internal/services/certificates/renewal_service.go`,
`internal/container/service_container.go`

**Symptom**: a caller holding `certificates/restore` in vault B could restore
a certificate whose `key_id` and `ca_cert_id` named a key and a CA
certificate in vault A. The auto-renew scheduler then renewed the row with
`model.NewAdminScope(cert.UserID)`. An admin scope's predicate is `1 = 1`
(`scope_predicate.go`), so `ValidateKeyOwnership` and
`ValidateCertificateAccess` read the vault-A objects, and the renewal copied
the vault-A key's private PEM into the vault-B row. When the restored body
was a CA, the renewed row was a working CA in vault B signed by a vault-A
key. The owner comparison those validators keep (B32) was the only barrier,
and it passes whenever the restorer owns the vault-A objects, including
after their access to vault A was revoked. The blob was unauthenticated
base64url JSON, so the links did not even need a real backup: they could be
written by hand. The same format let a forged key blob bind a new key row to
any `pkcs11:<label>` HSM handle.

**Root cause**: three layers, each enough to matter. `RestoreCertificate`
overwrote only `ID`, `UserID` and `VaultID` (the B15 fix), and the
repository inserted `key_id`/`ca_cert_id` verbatim; `Update` never rewrites
`ca_cert_id`, deliberately (B37), so nothing later corrected it. The blob
carried no integrity protection. The scheduler used an admin scope, so the
B32 vault predicate never applied on the renewal path.

**What was fixed**:

- Blobs are sealed. `BackupSecret`/`BackupKey`/`BackupCertificate` return
  `rvb2.` followed by `common.EncryptWithKey` output under a key derived from
  the master key with HKDF-SHA256 (info `rocketvault item-backup blob seal
  v2`). Restore refuses a blob with no prefix (`ErrUnsealedBlob`), a blob
  that fails authentication (`ErrBlobAuthentication`), and runs nothing at
  all while no seal key is set (`ErrSealKeyUnset`). The first two wrap
  `ErrInvalidBlob`, so HTTP reports 400.
- `RestoreCertificate` keeps `key_id` and `ca_cert_id` only when each reads
  under `model.NewVaultScope(targetVault, restorer)`; otherwise it clears
  them. Cleared, not rejected: cross-vault restore is supported (B15), and
  every consequence of a cleared link is a later refusal, never a grant.
- The scheduler renews with `model.NewVaultScope(cert.VaultID,
  cert.UserID)`, and skips a row with no vault.

**Compatibility decision**: blobs taken before the upgrade are refused, with
no opt-in. An accepted-unsealed path would be the forgery path, since a
pre-upgrade blob and a hand-written one cannot be told apart. The loss is
smaller than it looks: a blob's values were always ciphertext under the
master key, so blobs never survived a master-key rotation or moved between
instances anyway. Operators re-take backups after upgrading.

**HSM-handle decision**: sealing closes the forged-handle case. A genuine
blob of an HSM key restored into another vault still points at the same HSM
object. That is what backup plus restore means (the caller held
`keys/backup` in the source vault), and it is accepted as-is.

**Accepted limitation**: a backup handler that hits `ErrSealKeyUnset`
reports it as 404, because the three backup handlers map every service
error to not-found. The container always sets the key when the master key
parses, and `bootstrap.ValidateMasterKey` refuses to start otherwise, so
this is reachable only in a hand-built container.

**Pinned by**: `TestRestoreCertificate_RejectsLegacyUnsealedBlob`,
`TestRestoreKey_RejectsForgedHSMHandle`, `TestRestore_RejectsTamperedBlob`,
`TestRestore_RejectsBlobSealedUnderAnotherMasterKey`,
`TestItemBackup_FailsClosedWithoutSealKey`
(`internal/backup/item_backup_seal_test.go`);
`TestRestoreCertificate_DropsCrossVaultReferences`,
`TestRestoreCertificate_KeepsSameVaultReferences`,
`TestRestoreCertificate_NoKeyRepoDropsKeyReference`
(`internal/backup/item_backup_cert_refs_test.go`);
`TestRestoreCertificateHandler_LegacyUnsealedBlob_Returns400`
(`api/backup_item_seal_test.go`);
`TestItemBackupService_SealedWhenMasterKeyConfigured`
(`internal/container/item_backup_seal_test.go`);
`TestCheckAndRenewCertificates_AutoRenew`,
`TestCheckAndRenewCertificates_NilVaultSkipped`
(`internal/services/certificates/renewal_service_test.go`).

---
```

Replace `<N>` with the issue number printed above.

- [ ] **Step 6: Commit**

Stage `internal/backup/item_backup.go`, `internal/backup/item_backup_cert_refs_test.go`, `.claude/known-bugs.md`, then invoke the `dev-workflow-skills:1-git-commit` skill via the Skill tool. Subject should say certificate restore drops key and CA links that do not resolve in the target vault (B76). Footer: `Fixes #<N>` with the issue number from Step 5.

---

### Task 4: One shared data-plane access check for HTTP, CLI and scheduler (B77 groundwork)

**Files:**
- Modify: `internal/services/authorization/data_action_authz.go`
- Create: `internal/services/authorization/data_plane_access_test.go`
- Modify: `cmd/vaultcli/vault.go:49-67` (`RequireDataAction`)
- Modify: `cmd/vaultcli/session.go` (imports, new method `RequireAlso` after `Authorize`)

**Interfaces:**
- Consumes: `AccessPolicyService.CheckAccess(ctx, principalID, resourceType, op, vaultID) (AccessDecision, error)`, `RoleAssignmentService.HasDataAction(ctx, principalID, vaultID, action) (bool, error)`.
- Produces:
  - `var ErrDataPlaneDenied = errors.New("forbidden")` in package `authorization`
  - `func RequireDataPlaneAccess(ctx context.Context, policies AccessPolicyService, roles RoleAssignmentService, principalID, vaultID uuid.UUID, resourceType model.PolicyResourceType, op model.PolicyOperation, action model.DataAction) error`
  - `func (s *Session) RequireAlso(action model.DataAction, op model.PolicyOperation) error` in package `vaultcli`
  - `RequireDataAction` (authorization) keeps its message `forbidden: no role grants <action> in this vault`, now wrapping `ErrDataPlaneDenied`.

- [ ] **Step 1: Write the failing tests**

Create `internal/services/authorization/data_plane_access_test.go`:

```go
package authorization

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"rocketvault/model"
)

func TestRequireDataPlaneAccess_ExplicitDenyWinsOverRoleGrant(t *testing.T) {
	policies := &fakeAccessPolicyService{decision: AccessDenied}
	roles := &fakeRoleAssignmentService{hasAction: true}

	err := RequireDataPlaneAccess(context.Background(), policies, roles, uuid.New(), uuid.New(),
		model.PolicyResourceKeys, model.OpSign, model.ActionKeysSign)
	require.ErrorIs(t, err, ErrDataPlaneDenied)
	require.Contains(t, err.Error(), "explicit access policy")
}

func TestRequireDataPlaneAccess_NoRoleGrantIsDenied(t *testing.T) {
	policies := &fakeAccessPolicyService{decision: AccessFallback}
	roles := &fakeRoleAssignmentService{hasAction: false}

	err := RequireDataPlaneAccess(context.Background(), policies, roles, uuid.New(), uuid.New(),
		model.PolicyResourceKeys, model.OpSign, model.ActionKeysSign)
	require.ErrorIs(t, err, ErrDataPlaneDenied)
	require.Contains(t, err.Error(), "forbidden: no role grants")
}

func TestRequireDataPlaneAccess_GrantPassesAndForwardsArguments(t *testing.T) {
	policies := &fakeAccessPolicyService{decision: AccessFallback}
	roles := &fakeRoleAssignmentService{hasAction: true}
	principalID, vaultID := uuid.New(), uuid.New()

	err := RequireDataPlaneAccess(context.Background(), policies, roles, principalID, vaultID,
		model.PolicyResourceKeys, model.OpSign, model.ActionKeysSign)
	require.NoError(t, err)
	require.Equal(t, principalID, roles.calledPrincipalID)
	require.Equal(t, vaultID, roles.calledVaultID)
	require.Equal(t, model.ActionKeysSign, roles.calledAction)
}

func TestRequireDataPlaneAccess_NilServicesFailClosed(t *testing.T) {
	err := RequireDataPlaneAccess(context.Background(), nil, nil, uuid.New(), uuid.New(),
		model.PolicyResourceKeys, model.OpSign, model.ActionKeysSign)
	require.ErrorIs(t, err, ErrDataPlaneDenied)
}

func TestRequireDataPlaneAccess_PolicyLookupErrorIsNotADenial(t *testing.T) {
	lookup := errors.New("db exploded")
	policies := &fakeAccessPolicyService{err: lookup}
	roles := &fakeRoleAssignmentService{hasAction: true}

	err := RequireDataPlaneAccess(context.Background(), policies, roles, uuid.New(), uuid.New(),
		model.PolicyResourceKeys, model.OpSign, model.ActionKeysSign)
	require.ErrorIs(t, err, lookup)
	require.NotErrorIs(t, err, ErrDataPlaneDenied, "a lookup failure is a server fault, not a 403")
}

func TestRequireDataAction_DenialWrapsSentinel(t *testing.T) {
	roles := &fakeRoleAssignmentService{hasAction: false}
	err := RequireDataAction(context.Background(), roles, uuid.New(), uuid.New(), model.ActionKeysSign)
	require.ErrorIs(t, err, ErrDataPlaneDenied)
	require.Equal(t, "forbidden: no role grants "+string(model.ActionKeysSign)+" in this vault", err.Error())
}
```

- [ ] **Step 2: Run the tests and confirm they fail**

Run: `go test ./internal/services/authorization/ -run 'RequireDataPlaneAccess|DenialWrapsSentinel' -v`
Expected: FAIL at build time: `undefined: RequireDataPlaneAccess`, `undefined: ErrDataPlaneDenied`.

- [ ] **Step 3: Implement the helper**

Replace the whole of `internal/services/authorization/data_action_authz.go` with:

```go
package authorization

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"

	"rocketvault/model"
)

// ErrDataPlaneDenied marks a data-plane authorization refusal: an explicit
// deny policy, or no role granting the action. Its text is "forbidden", so
// every message built on it keeps the "forbidden: ..." shape callers and
// tests already match. A lookup failure never wraps it.
var ErrDataPlaneDenied = errors.New("forbidden")

// RequireDataAction returns nil if principalID holds a role assignment in
// vaultID granting action, and an error otherwise. It is the CLI-callable
// equivalent of the role-assignment half of PolicyMiddleware's check (its
// "2. Deny-by-default for vault data-plane routes" step) and must stay
// behaviorally identical to it: no admin short-circuit. Data-plane access
// has none today, even over HTTP (unlike vault-management's CanManageVault/
// CanPurgeVault, which do short-circuit for the global admin role) — copying
// that idiom here would grant the CLI a bypass the HTTP API doesn't have.
//
// This function alone is NOT full parity with PolicyMiddleware: it doesn't
// check the access_policies explicit-deny override. RequireDataPlaneAccess
// wraps both steps in the correct order; call that instead.
func RequireDataAction(ctx context.Context, roles RoleAssignmentService, principalID, vaultID uuid.UUID, action model.DataAction) error {
	ok, err := roles.HasDataAction(ctx, principalID, vaultID, action)
	if err != nil {
		return fmt.Errorf("checking vault authorization: %w", err)
	}
	if !ok {
		return fmt.Errorf("%w: no role grants %s in this vault", ErrDataPlaneDenied, action)
	}
	return nil
}

// RequireDataPlaneAccess runs PolicyMiddleware's full two-stage data-plane
// check for one action in one vault: first the access_policies explicit-deny
// override, then the deny-by-default role-assignment check. It is the single
// implementation behind the CLI (cmd/vaultcli), handlers that need a second
// action beyond the one their route maps to, and the renewal scheduler, so
// the three cannot drift apart. Nil services deny.
func RequireDataPlaneAccess(
	ctx context.Context,
	policies AccessPolicyService,
	roles RoleAssignmentService,
	principalID, vaultID uuid.UUID,
	resourceType model.PolicyResourceType,
	op model.PolicyOperation,
	action model.DataAction,
) error {
	if policies == nil || roles == nil {
		return fmt.Errorf("%w: authorization services are not available", ErrDataPlaneDenied)
	}

	decision, err := policies.CheckAccess(ctx, principalID, resourceType, op, vaultID)
	if err != nil {
		return fmt.Errorf("checking access policy: %w", err)
	}
	if decision == AccessDenied {
		return fmt.Errorf("%w: access denied by an explicit access policy for %s", ErrDataPlaneDenied, action)
	}

	return RequireDataAction(ctx, roles, principalID, vaultID, action)
}
```

- [ ] **Step 4: Route the CLI through the helper**

In `cmd/vaultcli/vault.go`, replace the body of `RequireDataAction` (from `vaultID, err := ResolveVaultID(ctx, cmd, sc)` through the final `return vaultID, nil`) with:

```go
	vaultID, err := ResolveVaultID(ctx, cmd, sc)
	if err != nil {
		return uuid.Nil, err
	}

	// One implementation for the CLI, HTTP handlers and the renewal
	// scheduler, so the two-stage order cannot drift between them.
	if err := authorization.RequireDataPlaneAccess(ctx, sc.GetAccessPolicyService(), sc.GetRoleAssignmentService(),
		principalID, vaultID, resourceTypeFromAction(action), op, action); err != nil {
		return uuid.Nil, err
	}
	return vaultID, nil
```

In `cmd/vaultcli/session.go`, add `"rocketvault/internal/services/authorization"` to the imports, and add after `Authorize`:

```go
// RequireAlso runs Authorize's two-stage check for one more data action, in
// the vault Authorize already resolved. It is for commands that act on two
// object types at once, such as issuing a certificate with a key. Calling it
// before Authorize fails closed.
func (s *Session) RequireAlso(action model.DataAction, op model.PolicyOperation) error {
	msg := s.op.AuthzFailMsg
	if msg == "" {
		msg = "vault authorization failed"
	}
	if s.Container == nil || s.VaultID == uuid.Nil {
		return s.Fail(msg, fmt.Errorf("RequireAlso called before Authorize"))
	}

	if err := authorization.RequireDataPlaneAccess(s.Ctx, s.Container.GetAccessPolicyService(),
		s.Container.GetRoleAssignmentService(), s.Claims.UserID, s.VaultID,
		resourceTypeFromAction(action), op, action); err != nil {
		return s.Fail(msg, err)
	}
	return nil
}
```

- [ ] **Step 5: Run the tests and confirm they pass**

Run: `go test ./internal/services/authorization/ ./cmd/...`
Expected: PASS. Existing CLI denial tests still see the same `forbidden: ...` messages.

- [ ] **Step 6: Commit**

Stage the files of this task, then invoke the `dev-workflow-skills:1-git-commit` skill via the Skill tool. Subject should say the data-plane two-stage check is extracted into `authorization.RequireDataPlaneAccess` and shared by the CLI. No footer.

---

### Task 5: Refuse revoked, disabled or out-of-window signing keys (B77)

**Files:**
- Modify: `internal/services/certificates/certificate_service.go:25-31` (sentinels), `:1078-1093` (`ValidateKeyOwnership`)
- Create: `internal/services/certificates/signing_key_lifecycle_test.go`
- Modify (fixtures): every `model.Key{` literal lacking `Enabled` in `internal/services/certificates/*_test.go`

**Interfaces:**
- Consumes: `(*model.Key).IsAccessible() bool` (`model/key.go:34`), field `model.Key.Revoked`.
- Produces: `var ErrSigningKeyUnusable = errors.New("signing key is revoked, disabled or outside its valid time window")` in package `certificates`. `ValidateKeyOwnership` returns an error wrapping it for a revoked or inaccessible key. Create (both paths) and `RenewCertificate` inherit the check because they already call `ValidateKeyOwnership`.

- [ ] **Step 1: Write the failing tests**

Create `internal/services/certificates/signing_key_lifecycle_test.go`:

```go
package certificates

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"rocketvault/model"
)

// TestValidateKeyOwnership_RefusesUnusableKey is the B77 regression. The key
// crypto path refuses these keys in loadAndAuthorize; issuing or renewing a
// certificate signs with the key, so it must refuse them too.
func TestValidateKeyOwnership_RefusesUnusableKey(t *testing.T) {
	t.Parallel()

	past := time.Now().Add(-time.Hour)
	future := time.Now().Add(time.Hour)
	cases := []struct {
		name string
		key  model.Key
	}{
		{"revoked", model.Key{Enabled: true, Revoked: true}},
		{"disabled", model.Key{Enabled: false}},
		{"expired", model.Key{Enabled: true, ExpiresAt: &past}},
		{"not yet active", model.Key{Enabled: true, NotBefore: &future}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			userID, keyID, vaultID := uuid.New(), uuid.New(), uuid.New()
			key := tc.key
			key.ID, key.UserID, key.VaultID = keyID, userID, vaultID
			keyRepo := &mockKeyRepo{}
			vaultScopedKeyRepo(keyRepo, keyID, vaultID, &key)

			svc := newCertSvc(&mockCertRepository{}, keyRepo)
			err := svc.ValidateKeyOwnership(context.Background(), keyID, model.NewVaultScope(vaultID, userID))
			require.ErrorIs(t, err, ErrSigningKeyUnusable)
		})
	}
}

func TestValidateKeyOwnership_AcceptsUsableKey(t *testing.T) {
	t.Parallel()

	future := time.Now().Add(time.Hour)
	userID, keyID, vaultID := uuid.New(), uuid.New(), uuid.New()
	keyRepo := &mockKeyRepo{}
	vaultScopedKeyRepo(keyRepo, keyID, vaultID, &model.Key{
		ID: keyID, UserID: userID, VaultID: vaultID, Enabled: true, ExpiresAt: &future,
	})

	svc := newCertSvc(&mockCertRepository{}, keyRepo)
	require.NoError(t, svc.ValidateKeyOwnership(context.Background(), keyID, model.NewVaultScope(vaultID, userID)))
}

func TestCreateSelfSignedCertificate_RefusesRevokedKey(t *testing.T) {
	t.Parallel()

	userID, keyID, vaultID := uuid.New(), uuid.New(), uuid.New()
	keyRepo := &mockKeyRepo{}
	vaultScopedKeyRepo(keyRepo, keyID, vaultID, &model.Key{
		ID: keyID, UserID: userID, VaultID: vaultID, Enabled: true, Revoked: true,
	})
	certRepo := &mockCertRepository{}

	svc := newCertSvc(certRepo, keyRepo)
	_, err := svc.CreateSelfSignedCertificate(context.Background(), CreateCertificateRequest{
		Name: "revoked-key-cert", KeyID: keyID, ValidityDays: 30, UserID: userID, VaultID: vaultID,
	})
	require.ErrorIs(t, err, ErrSigningKeyUnusable)
	certRepo.AssertNotCalled(t, "Create", mock.Anything, mock.Anything)
}

func TestRenewCertificate_RefusesDisabledKey(t *testing.T) {
	t.Parallel()

	userID, keyID, vaultID, certID := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	scope := model.NewVaultScope(vaultID, userID)
	certRepo := &mockCertRepository{}
	certRepo.On("Read", mock.Anything, certID, scope).Return(&model.Certificate{
		ID: certID, UserID: userID, VaultID: vaultID, KeyID: keyID, Name: "c", Enabled: true,
	}, nil)
	keyRepo := &mockKeyRepo{}
	vaultScopedKeyRepo(keyRepo, keyID, vaultID, &model.Key{
		ID: keyID, UserID: userID, VaultID: vaultID, Enabled: false,
	})

	svc := newCertSvc(certRepo, keyRepo)
	_, err := svc.RenewCertificate(context.Background(), certID, scope, 30)
	require.ErrorIs(t, err, ErrSigningKeyUnusable)
	certRepo.AssertNotCalled(t, "Update", mock.Anything, mock.Anything, mock.Anything)
}
```

- [ ] **Step 2: Run the tests and confirm they fail**

Run: `go test ./internal/services/certificates/ -run 'RefusesUnusableKey|AcceptsUsableKey|RefusesRevokedKey|RefusesDisabledKey' -v`
Expected: FAIL at build time: `undefined: ErrSigningKeyUnusable`.

- [ ] **Step 3: Implement**

In `internal/services/certificates/certificate_service.go`, after the `ErrCertLifecycleDenied` declaration (line 31), add:

```go
// ErrSigningKeyUnusable is returned when a certificate's signing key, or the
// key linked to its signing CA, is revoked, disabled, or outside its validity
// window (B77).
var ErrSigningKeyUnusable = errors.New("signing key is revoked, disabled or outside its valid time window")
```

In `ValidateKeyOwnership`, replace

```go
	if key.UserID != actorID {
		s.logger.LogAuditError(actorID.String(), "validate_key_ownership", "failed", "forbidden: cannot use other users' keys", nil)
		return fmt.Errorf("forbidden: cannot use other users' keys")
	}

	return nil
}
```

with

```go
	if key.UserID != actorID {
		s.logger.LogAuditError(actorID.String(), "validate_key_ownership", "failed", "forbidden: cannot use other users' keys", nil)
		return fmt.Errorf("forbidden: cannot use other users' keys")
	}

	// Issuing or renewing a certificate signs with the key, so it refuses the
	// same keys the key crypto path refuses in loadAndAuthorize (B77).
	if key.Revoked || !key.IsAccessible() {
		s.logger.LogAuditError(actorID.String(), "validate_key_ownership", "failed",
			"signing key is revoked, disabled or outside its valid time window", nil)
		return fmt.Errorf("%w: %s", ErrSigningKeyUnusable, keyID)
	}

	return nil
}
```

Also extend the doc comment's bullet list above `ValidateKeyOwnership` with a third bullet:

```go
//   - The key must be usable: not revoked, enabled, and inside its validity
//     window, matching loadAndAuthorize in the key crypto path (B77).
```

- [ ] **Step 4: Fix the key fixtures the new gate now refuses**

Most existing fixtures build `model.Key` without `Enabled`, whose zero value is false. Add `Enabled: true` to every `model.Key` literal in `internal/services/certificates/*_test.go` that does not already set it. Verified locations at the time of writing:

- `ca_opt_in_test.go`: literals starting at lines 69, 209, 467
- `cert_soft_delete_test.go`: 299, 459, 512, 558
- `ca_renewal_scheduler_test.go`: 69
- `ca_renewal_test.go`: 104, 194, 381, 430
- `certificate_service_extended_test.go`: 597, 768, 1118, 1157, 1205, 1247, 1277, 1324, 1385, 1436, 1485, 1528

For one-line literals such as `&model.Key{ID: keyID, UserID: userID, Type: model.KeyTypeRSA, Value: encEntity}`, write `&model.Key{ID: keyID, UserID: userID, Type: model.KeyTypeRSA, Value: encEntity, Enabled: true}`. For multi-line literals add an `Enabled: true,` line before the closing brace. Leave the four literals inside `signing_key_lifecycle_test.go` as written.

Run: `grep -n "model.Key{" internal/services/certificates/*_test.go` and confirm every hit outside `signing_key_lifecycle_test.go` sets `Enabled: true` (for multi-line literals, read the following lines).

- [ ] **Step 5: Run the tests and confirm they pass**

Run: `go test ./internal/services/certificates/`
Expected: PASS.

- [ ] **Step 6: Commit**

Stage `internal/services/certificates/certificate_service.go` and the changed test files, then invoke the `dev-workflow-skills:1-git-commit` skill via the Skill tool. Subject should say certificate issuance and renewal refuse revoked, disabled or out-of-window keys (B77). No footer yet.

---

### Task 6: A CA certificate signs only while its own linked key is usable (B77, key revocation decision)

**Files:**
- Modify: `internal/services/certificates/certificate_service.go` (new method `requireCAKeyUsable` after `ValidateKeyOwnership`; call sites in `CreateCASignedCertificate` after the `caStatus != caStatusCA` block at `:423-426`, and in `renewCASignedBody` after its `caStatus != caStatusCA` block at `:814-817`)
- Modify: `internal/services/certificates/signing_key_lifecycle_test.go` (append tests and helper)
- Modify: `internal/services/certificates/ca_renewal_test.go:20-123` (fixture)
- Modify (fixtures): the CA-signed tests the gate newly refuses

**Interfaces:**
- Consumes: `ErrSigningKeyUnusable` (Task 5).
- Produces: unexported `(s *certificateService) requireCAKeyUsable(ctx context.Context, caCert *model.Certificate, scope model.Scope) error`; test helper `linkUsableCAKey(keyRepo *mockKeyRepo, caCert *model.Certificate, scope any)`; `caRenewalFixture.caKey *model.Key`.

Decision recorded here and in § B77: a certificate row stores a copy of its key's private PEM, and that copy is only ever used as a CA signing key (`caCert.PrivateKey` in `CreateCASignedCertificate` and `renewCASignedBody`; no API returns it). Revoking, disabling or expiring the key therefore stops that CA from issuing or renewing anything, because both paths now consult the CA row's linked key. Certificates already issued are not revoked, disabled or deleted: that would be a destructive cross-object side effect of a key operation, Azure does not cascade either, and X.509 revocation is a separate concern. The embedded PEM is not erased at rest. A CA row with no key link is refused as a signer: every CA that can pass `inspectCertificateCA` was issued after the `key_id` column existed (the keyCertSign fix, B43, came later), so the only such rows are ones whose link was dropped at restore (Task 3), whose key cannot be checked.

- [ ] **Step 1: Write the failing tests**

Append to `internal/services/certificates/signing_key_lifecycle_test.go` (add `"errors"`, `"rocketvault/common"` and `"rocketvault/internal/crypto"` to its imports):

```go
// linkUsableCAKey gives a CA certificate fixture an enabled signing key and
// registers the key read the CA-key gate performs (B77).
func linkUsableCAKey(keyRepo *mockKeyRepo, caCert *model.Certificate, scope any) {
	caKeyID := uuid.New()
	caCert.KeyID = caKeyID
	keyRepo.On("Read", mock.Anything, caKeyID, scope).Return(&model.Key{
		ID: caKeyID, UserID: caCert.UserID, VaultID: caCert.VaultID, Enabled: true,
	}, nil)
}

func TestRequireCAKeyUsable(t *testing.T) {
	t.Parallel()

	userID, vaultID := uuid.New(), uuid.New()
	scope := model.NewVaultScope(vaultID, userID)
	past := time.Now().Add(-time.Hour)

	withKey := func(t *testing.T, key *model.Key, readErr error) error {
		t.Helper()
		keyRepo := &mockKeyRepo{}
		caKeyID := uuid.New()
		if readErr != nil {
			keyRepo.On("Read", mock.Anything, caKeyID, scope).Return(nil, readErr)
		} else {
			key.ID = caKeyID
			keyRepo.On("Read", mock.Anything, caKeyID, scope).Return(key, nil)
		}
		svc := newCertSvc(&mockCertRepository{}, keyRepo).(*certificateService)
		return svc.requireCAKeyUsable(context.Background(), &model.Certificate{ID: uuid.New(), KeyID: caKeyID}, scope)
	}

	t.Run("no key link is refused", func(t *testing.T) {
		svc := newCertSvc(&mockCertRepository{}, &mockKeyRepo{}).(*certificateService)
		err := svc.requireCAKeyUsable(context.Background(), &model.Certificate{ID: uuid.New()}, scope)
		require.ErrorIs(t, err, ErrSigningKeyUnusable)
	})
	t.Run("revoked key is refused", func(t *testing.T) {
		require.ErrorIs(t, withKey(t, &model.Key{Enabled: true, Revoked: true}, nil), ErrSigningKeyUnusable)
	})
	t.Run("expired key is refused", func(t *testing.T) {
		require.ErrorIs(t, withKey(t, &model.Key{Enabled: true, ExpiresAt: &past}, nil), ErrSigningKeyUnusable)
	})
	t.Run("key outside the vault is refused", func(t *testing.T) {
		require.ErrorIs(t, withKey(t, nil, errors.New("key not found or access denied")), ErrSigningKeyUnusable)
	})
	t.Run("usable key passes", func(t *testing.T) {
		require.NoError(t, withKey(t, &model.Key{Enabled: true}, nil))
	})
}

// TestCreateCASignedCertificate_RefusesCAWithRevokedKey is the creation half
// of the revocation decision: the CA row's embedded copy of a revoked key
// must not keep signing.
func TestCreateCASignedCertificate_RefusesCAWithRevokedKey(t *testing.T) {
	setupMasterKey()

	userID, keyID, caCertID, caKeyID := uuid.New(), uuid.New(), uuid.New(), uuid.New()

	entityKeyPEM, err := crypto.GenerateRSAKeyPEM(2048)
	require.NoError(t, err)
	caKeyPEM, err := crypto.GenerateRSAKeyPEM(2048)
	require.NoError(t, err)
	caCertPEM, err := crypto.CreateSelfSignedCertificatePEM(caKeyPEM, "RSA", crypto.CertificateTemplate{
		CommonName: "Revoked-key CA", ValidityDays: 3650, IsCA: true,
	})
	require.NoError(t, err)
	encEntity, err := common.EncryptSecret(entityKeyPEM)
	require.NoError(t, err)
	encCA, err := common.EncryptSecret(caKeyPEM)
	require.NoError(t, err)

	certRepo := &mockCertRepository{}
	keyRepo := &mockKeyRepo{}
	keyRepo.On("Read", mock.Anything, keyID, certVaultScope(userID)).
		Return(&model.Key{ID: keyID, UserID: userID, Type: model.KeyTypeRSA, Value: encEntity, Enabled: true}, nil)
	keyRepo.On("Read", mock.Anything, caKeyID, certVaultScope(userID)).
		Return(&model.Key{ID: caKeyID, UserID: userID, Type: model.KeyTypeRSA, Enabled: true, Revoked: true}, nil)
	certRepo.On("Read", mock.Anything, caCertID, certVaultScope(userID)).Return(&model.Certificate{
		ID: caCertID, UserID: userID, KeyID: caKeyID, Name: "revoked-key-ca",
		Certificate: caCertPEM, PrivateKey: encCA, Enabled: true,
	}, nil)
	// No Create stub: creation must stop before storing anything.

	svc := newCertSvc(certRepo, keyRepo)
	_, err = svc.CreateCASignedCertificate(context.Background(), CreateCertificateRequest{
		Name: "entity-cert", KeyID: keyID, ValidityDays: 365, UserID: userID, CACertID: &caCertID,
	})
	require.ErrorIs(t, err, ErrSigningKeyUnusable)
	certRepo.AssertNotCalled(t, "Create", mock.Anything, mock.Anything)
}
```

In `internal/services/certificates/ca_renewal_test.go`, change the fixture:
- add `caKey *model.Key` as the last field of `caRenewalFixture`;
- after `caCertID := uuid.New()` in `newCARenewalFixture` add `caKeyID := uuid.New()`;
- in the `caCert` literal add `KeyID:       caKeyID,` after `VaultID:     vaultID,`;
- after the entity key's `keyRepo.On("Read", ...)` expectation add:

```go
	caKey := &model.Key{ID: caKeyID, UserID: userID, VaultID: vaultID, Type: caKeyType, Enabled: true}
	keyRepo.On("Read", mock.Anything, caKeyID, scope).Return(caKey, nil)
```

- in the returned struct literal add `caKey:    caKey,`.

Then append to `ca_renewal_test.go`:

```go
// The renewal half of the revocation decision (B77): once the CA's own key
// is revoked, its embedded copy must not re-sign anything.
func TestRenewCertificate_RevokedCAKeyRefusesRenewal(t *testing.T) {
	f := newCARenewalFixture(t, "RSA")
	f.caKey.Revoked = true

	_, err := f.svc.RenewCertificate(context.Background(), f.certID, f.scope, 365)
	require.ErrorIs(t, err, ErrSigningKeyUnusable)
	f.certRepo.AssertNotCalled(t, "Update", mock.Anything, mock.Anything, mock.Anything)
}
```

- [ ] **Step 2: Run the tests and confirm they fail**

Run: `go test ./internal/services/certificates/ -run 'TestRequireCAKeyUsable|RefusesCAWithRevokedKey|RevokedCAKeyRefusesRenewal' -v`
Expected: FAIL at build time: `svc.requireCAKeyUsable undefined`.

- [ ] **Step 3: Implement**

In `certificate_service.go`, after `ValidateKeyOwnership`, add:

```go
// requireCAKeyUsable refuses to sign through a CA certificate whose own
// linked key is revoked, disabled, outside its validity window, or no longer
// readable in scope. The CA row stores a copy of that key's private PEM, so
// without this check revoking the key would not stop the CA from issuing
// (B77). A CA row with no key link is refused too: every CA that passes
// inspectCertificateCA was issued after key_id existed, so a missing link
// means it was dropped at restore (B76) and the key cannot be checked.
func (s *certificateService) requireCAKeyUsable(ctx context.Context, caCert *model.Certificate, scope model.Scope) error {
	if caCert.KeyID == uuid.Nil {
		return fmt.Errorf("%w: CA certificate %s records no signing key", ErrSigningKeyUnusable, caCert.ID)
	}
	key, err := s.keyRepo.Read(ctx, caCert.KeyID, scope)
	if err != nil {
		return fmt.Errorf("%w: CA signing key %s is not readable: %w", ErrSigningKeyUnusable, caCert.KeyID, err)
	}
	if key.Revoked || !key.IsAccessible() {
		return fmt.Errorf("%w: CA signing key %s", ErrSigningKeyUnusable, caCert.KeyID)
	}
	return nil
}
```

In `CreateCASignedCertificate`, replace

```go
	if caStatus != caStatusCA {
		s.logger.LogAuditError(req.UserID.String(), "create_ca_signed_cert", "failed", "CA certificate cannot sign certificates", nil)
		return nil, fmt.Errorf("signing CA %s cannot sign certificates (asserts CA without keyCertSign, or is not a CA); reissue it with --is-ca", *req.CACertID)
	}
```

with

```go
	if caStatus != caStatusCA {
		s.logger.LogAuditError(req.UserID.String(), "create_ca_signed_cert", "failed", "CA certificate cannot sign certificates", nil)
		return nil, fmt.Errorf("signing CA %s cannot sign certificates (asserts CA without keyCertSign, or is not a CA); reissue it with --is-ca", *req.CACertID)
	}

	// The CA signs with its row's embedded copy of its key, so that key's
	// lifecycle decides whether it may still sign (B77).
	if err := s.requireCAKeyUsable(ctx, caCert, certScope); err != nil {
		s.logger.LogAuditError(req.UserID.String(), "create_ca_signed_cert", "failed", "CA signing key is unusable", err)
		return nil, fmt.Errorf("cannot issue a CA-signed certificate: %w", err)
	}
```

In `renewCASignedBody`, replace

```go
	if caStatus != caStatusCA {
		s.logger.LogAuditError(userID.String(), "renew_certificate", "failed", "signing CA certificate cannot sign certificates", nil)
		return "", fmt.Errorf("signing CA %s cannot sign certificates (asserts CA without keyCertSign, or is not a CA); reissue it with --is-ca", caCertID)
	}
```

with

```go
	if caStatus != caStatusCA {
		s.logger.LogAuditError(userID.String(), "renew_certificate", "failed", "signing CA certificate cannot sign certificates", nil)
		return "", fmt.Errorf("signing CA %s cannot sign certificates (asserts CA without keyCertSign, or is not a CA); reissue it with --is-ca", caCertID)
	}

	// See CreateCASignedCertificate: the CA's own key must still be usable.
	if err := s.requireCAKeyUsable(ctx, caCert, scope); err != nil {
		s.logger.LogAuditError(userID.String(), "renew_certificate", "failed", "signing CA key is unusable", err)
		return "", fmt.Errorf("cannot renew CA-signed certificate: %w", err)
	}
```

- [ ] **Step 4: Fix the CA fixtures the gate now refuses**

Run: `go test ./internal/services/certificates/ 2>&1 | grep -E '^--- FAIL|signing key is revoked'`

The gate sits after the `caStatus != caStatusCA` refusal, so only tests that build a real CA and expect a successful CA-signed issue or renewal reach it. The sweep is: hoist the inline CA literal where needed, then call `linkUsableCAKey(keyRepo, caCert, <scope>)` before the service call, passing the same scope the CA's `certRepo.On("Read", ...)` expectation uses. Verified by reading each file:

`internal/services/certificates/certificate_service_extended_test.go` (scope `certVaultScope(userID)`; `caCert` is already a variable in the first, fourth and fifth):
- `TestCreateCASignedCertificate_FullSuccess` (`:1298`): after `certRepo.On("Read", mock.Anything, caCertID, certVaultScope(userID)).Return(caCert, nil)` add `linkUsableCAKey(keyRepo, caCert, certVaultScope(userID))`.
- `TestCreateCASignedCertificate_StoresCACertID` (`:1359`): replace the inline `Return(&model.Certificate{ID: caCertID, UserID: userID, Name: "test-ca", Certificate: caCertPEM, PrivateKey: encCA, Enabled: true}, nil)` with a hoisted variable declared above the `certRepo.On("Read", ...)` line:

```go
	caCert := &model.Certificate{
		ID: caCertID, UserID: userID, Name: "test-ca",
		Certificate: caCertPEM, PrivateKey: encCA, Enabled: true,
	}
	linkUsableCAKey(keyRepo, caCert, certVaultScope(userID))
	certRepo.On("Read", mock.Anything, caCertID, certVaultScope(userID)).Return(caCert, nil)
```

- `TestCreateCASignedCertificate_ECDSACA` (`:1410`): the same hoist, with `Name: "ecdsa-ca"`, `Certificate: caCertPEM`, `PrivateKey: encCA`, `Enabled: true`.
- `TestCreateCASignedCertificate_RepoCreateFails` (`:1461`): `caCert` is already a variable, add `linkUsableCAKey(keyRepo, caCert, certVaultScope(userID))` before the `certRepo.On("Read", ...)` line.
- `TestCreateCASignedCertificate_WithExplicitEnabledFalse` (`:1508`): same as the previous one.

`internal/services/certificates/cert_soft_delete_test.go`:
- `TestCreateCASignedCertificate_SetsPurgeProtectionWhenRequested` (`:489`): hoist the inline CA literal (`ID: caCertID, UserID: userID, Name: "test-ca", Certificate: caCertPEM, PrivateKey: encryptedCAKey`) into `caCert := &model.Certificate{...}`, add `linkUsableCAKey(keyRepo, caCert, certVaultScope(userID))`, and return `caCert` from the `certRepo.On("Read", ...)` call. The test's `keyRepo.AssertExpectations(t)` still holds, because the CA key read is now made.

`internal/services/certificates/ca_renewal_scheduler_test.go`: `TestCheckAndRenewCertificates_CASignedKeepsIssuer` builds its CA as the variable `caCert`. Add `linkUsableCAKey(keyRepo, caCert, vaultScope)` before the `certRepo.On("Read", ...)` expectation for it (`keyRepo` and `vaultScope` are the names that test already uses after Task 1).

`internal/services/certificates/ca_renewal_test.go`: every renewal test that goes through `newCARenewalFixture` is covered by the fixture edit above (`caKey` on the CA row). Nothing else in the file needs the helper. Checked specifically: the `model.Key` literals at `:194`, `:381` and `:430` are not CA-signing keys. `:194` belongs to `TestRenewCertificate_SelfSignedStaysSelfSigned`, which has no `CACertID` and never calls the gate. `:381` and `:430` are the leaf-key reads of `TestCreateCASignedCertificate_PreFixPseudoCARefusesCreation` and `_LeafAsCARefusesCreation`, which are refused by the `caStatus` check before the gate. Those three literals only need `Enabled: true` from Step 4 of Task 5.

`internal/services/certificates/ca_opt_in_test.go`: no change. Its only CA-signed test, `TestCreateCASignedCertificate_RejectsCAOptIn`, is refused on `IsCA` before any read.

Run the suite to confirm nothing else needs the helper: `go test ./internal/services/certificates/ 2>&1 | grep -E '^--- FAIL|signing key is revoked'`. Any remaining failure whose error contains `signing key is revoked, disabled or outside its valid time window` is a CA-signed test missed here: apply the same hoist and `linkUsableCAKey` call. Tests that expect an earlier refusal (pseudo-CA, leaf-as-CA, missing CA) do not reach the gate and need no change. `cmd/certificates` tests mock the certificate service, so they are unaffected.

- [ ] **Step 5: Run the tests and confirm they pass**

Run: `go test ./internal/services/certificates/`
Expected: PASS.

- [ ] **Step 6: Commit**

Stage the files of this task, then invoke the `dev-workflow-skills:1-git-commit` skill via the Skill tool. Subject should say a CA certificate signs only while its linked key is usable (B77). No footer yet.

---

### Task 7: Issuing or renewing a certificate requires keys/sign, on HTTP and CLI (B77)

**Files:**
- Modify: `api/certificates.go:23-34` (imports), `:195-199` (after `certService` lookup in `createCertificate`)
- Modify: `api/certificates_test.go:167-170` (`certSvcContainer` fields), `:232-240` (policy and role getters), new tests
- Modify: `cmd/certificates/create.go:20-46` (Long help), `:84-87` (after `s.Authorize()`)
- Modify: `cmd/certificates/renew.go` (after `s.Authorize()`)
- Modify: `cmd/certificates/certs_cmd_test.go:593-635` (`TestCertCreateCmd_Authorized`), `:1286-1320` (`TestCertRenewCmd_Authorized`), new tests

**Interfaces:**
- Consumes: `authorization.RequireDataPlaneAccess`, `authorization.ErrDataPlaneDenied`, `(*vaultcli.Session).RequireAlso` (Task 4).
- Produces: HTTP `POST /certificates` and `POST /vaults/{name}/certificates` return 403 unless the caller holds `Microsoft.KeyVault/vaults/keys/sign/action` in the vault and no deny policy on `(keys, sign)` applies. `rocketvault certificate create` and `certificate renew` fail with `failed to create certificate` / `failed to renew certificate` under the same condition. There is no HTTP renew route (`api/certificates.go` registers none), so renew is CLI-only.

- [ ] **Step 1: Write the failing HTTP tests**

In `api/certificates_test.go`, change `certSvcContainer`:

```go
type certSvcContainer struct {
	certSvc        certServices.CertificateService
	certPolicyRepo repositories.CertificatePolicyRepositoryInterface
	// policySvc and roleSvc back createCertificate's keys/sign check. Nil
	// means allow, so tests that are not about that check need no setup.
	policySvc authzServices.AccessPolicyService
	roleSvc   authzServices.RoleAssignmentService
}
```

and replace its two getters

```go
func (c *certSvcContainer) GetAccessPolicyService() authzServices.AccessPolicyService {
	panic("unexpected call: GetAccessPolicyService")
}
func (c *certSvcContainer) GetRoleAssignmentService() authzServices.RoleAssignmentService {
	return nil
}
```

with

```go
func (c *certSvcContainer) GetAccessPolicyService() authzServices.AccessPolicyService {
	if c.policySvc != nil {
		return c.policySvc
	}
	allow := &mockAccessPolicyService{}
	allow.On("CheckAccess", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		Return(authzServices.AccessFallback, nil)
	return allow
}
func (c *certSvcContainer) GetRoleAssignmentService() authzServices.RoleAssignmentService {
	if c.roleSvc != nil {
		return c.roleSvc
	}
	allow := &mockRoleAssignmentService{}
	allow.On("HasDataAction", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(true, nil)
	return allow
}
```

Append the tests:

```go
// TestCreateCertificate_RequiresKeySign pins B77 on the HTTP path. The route
// maps to certificates/create only, but issuing a certificate signs with the
// key, so keys/sign is required in the same vault.
func TestCreateCertificate_RequiresKeySign(t *testing.T) {
	svc := &mockCertService{}
	roles := &mockRoleAssignmentService{}
	roles.On("HasDataAction", mock.Anything, uuid.MustParse(certTestUserID),
		uuid.MustParse(model.DefaultVaultID), model.ActionKeysSign).Return(false, nil)

	c := newCertCtx(svc, certAdminClaims())
	c.App.ServiceContainer.(*certSvcContainer).roleSvc = roles
	w := httptest.NewRecorder()
	body, _ := json.Marshal(map[string]any{
		"name": "mycert", "key_id": uuid.New().String(), "validity_days": 365,
	})
	r := httptest.NewRequest(http.MethodPost, "/certificates", bytes.NewReader(body))

	createCertificate(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusForbidden, w.Code)
	svc.AssertNotCalled(t, "CreateSelfSignedCertificate", mock.Anything, mock.Anything)
	roles.AssertExpectations(t)
}

// TestCreateCertificate_KeySignDenyPolicyRefuses pins the explicit-deny half:
// a deny on (keys, sign) blocks issuance even when a role would grant it.
func TestCreateCertificate_KeySignDenyPolicyRefuses(t *testing.T) {
	svc := &mockCertService{}
	policies := &mockAccessPolicyService{}
	policies.On("CheckAccess", mock.Anything, uuid.MustParse(certTestUserID), model.PolicyResourceKeys,
		model.OpSign, uuid.MustParse(model.DefaultVaultID)).Return(authzServices.AccessDenied, nil)

	c := newCertCtx(svc, certAdminClaims())
	c.App.ServiceContainer.(*certSvcContainer).policySvc = policies
	w := httptest.NewRecorder()
	body, _ := json.Marshal(map[string]any{
		"name": "mycert", "key_id": uuid.New().String(), "validity_days": 365,
	})
	r := httptest.NewRequest(http.MethodPost, "/certificates", bytes.NewReader(body))

	createCertificate(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusForbidden, w.Code)
	svc.AssertNotCalled(t, "CreateSelfSignedCertificate", mock.Anything, mock.Anything)
}
```

- [ ] **Step 2: Run the HTTP tests and confirm they fail**

Run: `go test ./api/ -run 'TestCreateCertificate' -v`
Expected: `TestCreateCertificate_RequiresKeySign` and `TestCreateCertificate_KeySignDenyPolicyRefuses` FAIL: the handler never consults the role or policy service and calls `CreateSelfSignedCertificate`, which the mock has no expectation for, so testify panics with `mock: I don't know what to return`. Every other `TestCreateCertificate_*` still passes with the allow-by-default getters.

- [ ] **Step 3: Implement the HTTP check**

In `api/certificates.go`, add `"errors"` to the stdlib imports and `authzServices "rocketvault/internal/services/authorization"` to the project imports. Replace

```go
	certService, svcOK := svc(c, container.ServiceContainerInterface.GetCertificateService)
	if !svcOK {
		return
	}

	createReq := certServices.CreateCertificateRequest{
```

with

```go
	certService, svcOK := svc(c, container.ServiceContainerInterface.GetCertificateService)
	if !svcOK {
		return
	}

	// Issuing a certificate signs with the named key. PolicyMiddleware only
	// checked certificates/create, so the caller must also hold keys/sign in
	// this vault, and a deny policy on key sign applies (B77). The CLI runs
	// the same check through vaultcli.Session.RequireAlso.
	if err := authzServices.RequireDataPlaneAccess(r.Context(),
		c.App.ServiceContainer.GetAccessPolicyService(), c.App.ServiceContainer.GetRoleAssignmentService(),
		userID, vaultID, model.PolicyResourceKeys, model.OpSign, model.ActionKeysSign); err != nil {
		if errors.Is(err, authzServices.ErrDataPlaneDenied) {
			c.SetPermissionError(string(model.ActionKeysSign))
			return
		}
		c.SetInternalError(err)
		return
	}

	createReq := certServices.CreateCertificateRequest{
```

Also update the comment at the top of `createCertificate` to:

```go
	// Authorization is two checks. PolicyMiddleware requires the
	// Microsoft.KeyVault/vaults/certificates/create data action, and the
	// handler below additionally requires keys/sign/action, because issuing
	// a certificate signs with the named key (B77).
```

Run: `go test ./api/ -run 'TestCreateCertificate' -v`
Expected: PASS.

- [ ] **Step 4: Write the failing CLI tests**

In `cmd/certificates/certs_cmd_test.go`, `TestCertCreateCmd_Authorized`, after the existing `roles.On(... model.ActionCertificatesCreate)...Once()` add:

```go
	roles.On("HasDataAction", mock.Anything, tc.TestUserID, tc.TestVaultID, model.ActionKeysSign).
		Return(true, nil).Once()
```

and after the existing `policies.On("CheckAccess", ... model.OpCreate, ...)...Once()` add:

```go
	policies.On("CheckAccess", mock.Anything, tc.TestUserID, model.PolicyResourceKeys, model.OpSign, tc.TestVaultID).
		Return(authzServices.AccessAllowed, nil).Once()
```

Make the same two additions to `TestCertRenewCmd_Authorized`.

Append:

```go
// TestCertCreateCmd_RequiresKeySign pins B77 on the CLI path: certificates/create
// alone is not enough, exactly as over HTTP.
func TestCertCreateCmd_RequiresKeySign(t *testing.T) {
	tc := testutils.NewTestContext(t)
	certSvc := &certCmdCertService{}
	keyID := uuid.New()

	roles := &testutils.MockRoleAssignmentService{}
	roles.On("HasDataAction", mock.Anything, tc.TestUserID, tc.TestVaultID, model.ActionCertificatesCreate).Return(true, nil)
	roles.On("HasDataAction", mock.Anything, tc.TestUserID, tc.TestVaultID, model.ActionKeysSign).Return(false, nil)
	tc.MockContainer.RoleAssignmentService = roles

	sc := &certsTestContainer{MockServiceContainer: tc.MockContainer, certSvc: certSvc}
	claims := &model.Claims{UserID: tc.TestUserID, Username: "admin", Roles: []string{model.RoleAdmin}}
	ctx := context.WithValue(context.Background(), common.ClaimsKey, claims)
	ctx = context.WithValue(ctx, common.LogKey, newCertLogger())
	ctx = context.WithValue(ctx, common.ServiceContainerKey, sc)
	ctx = context.WithValue(ctx, common.OutputFormatterKey, newCertFmtr())

	cmd, _ := newCertCmd(createCmd.RunE, nil)
	cmd.Flags().Bool("auto-renew", false, "")
	cmd.Flags().Int("renewal-days", 30, "")
	setFlags(cmd, map[string]any{"name": "mycert",
		"key-id":        keyID.String(),
		"validity-days": 365,
		"tags":          "",
		"ca-cert-id":    ""})
	cmd.SetContext(ctx)
	err := cmd.Execute()
	assert.ErrorContains(t, err, "failed to create certificate")
	assert.ErrorContains(t, err, string(model.ActionKeysSign))
	certSvc.AssertNotCalled(t, "CreateSelfSignedCertificate", mock.Anything, mock.Anything)
}

// TestCertRenewCmd_RequiresKeySign pins the same requirement for renewal.
func TestCertRenewCmd_RequiresKeySign(t *testing.T) {
	tc := testutils.NewTestContext(t)
	certSvc := &certCmdCertService{}
	certID := uuid.New()

	roles := &testutils.MockRoleAssignmentService{}
	roles.On("HasDataAction", mock.Anything, tc.TestUserID, tc.TestVaultID, model.ActionCertificatesCreate).Return(true, nil)
	roles.On("HasDataAction", mock.Anything, tc.TestUserID, tc.TestVaultID, model.ActionKeysSign).Return(false, nil)
	tc.MockContainer.RoleAssignmentService = roles

	sc := &certsTestContainer{MockServiceContainer: tc.MockContainer, certSvc: certSvc}
	claims := &model.Claims{UserID: tc.TestUserID, Roles: []string{model.RoleAdmin}}
	ctx := context.WithValue(context.Background(), common.ClaimsKey, claims)
	ctx = context.WithValue(ctx, common.LogKey, newCertLogger())
	ctx = context.WithValue(ctx, common.ServiceContainerKey, sc)

	cmd, _ := newCertCmd(renewCmd.RunE, []string{certID.String()})
	cmd.Args = cobra.ExactArgs(1)
	setFlags(cmd, map[string]any{"validity-days": 365})
	cmd.SetContext(ctx)
	err := cmd.Execute()
	assert.ErrorContains(t, err, "failed to renew certificate")
	certSvc.AssertNotCalled(t, "RenewCertificate", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
}
```

Run: `go test ./cmd/certificates/ -run 'RequiresKeySign|Authorized' -v`
Expected: FAIL. The two `RequiresKeySign` tests see the service called; the two `Authorized` tests fail `roles.AssertExpectations`/`policies.AssertExpectations` because the keys/sign expectations were never used.

- [ ] **Step 5: Implement the CLI check**

In `cmd/certificates/create.go`, replace

```go
		if err := s.Authorize(); err != nil {
			return err
		}
		certService := s.Container.GetCertificateService()

		// Create certificate request
```

with

```go
		if err := s.Authorize(); err != nil {
			return err
		}
		// Issuing a certificate signs with --key-id, so keys/sign is required
		// as well, exactly as the HTTP handler requires it (B77).
		if err := s.RequireAlso(model.ActionKeysSign, model.OpSign); err != nil {
			return err
		}
		certService := s.Container.GetCertificateService()

		// Create certificate request
```

In the same file's `Long` text, replace

```
Requires the admin or certificate_manager role, and the
Microsoft.KeyVault/vaults/certificates/create data action in the target
vault. The key named by --key-id must also be owned by the calling user, as
must the certificate named by --ca-cert-id.
```

with

```
Requires the admin or certificate_manager role, and both the
Microsoft.KeyVault/vaults/certificates/create and the
Microsoft.KeyVault/vaults/keys/sign/action data actions in the target vault
(for example Key Vault Certificates Officer plus Key Vault Crypto User). The
key named by --key-id must be owned by the calling user and be enabled, not
revoked, and inside its validity window. The certificate named by
--ca-cert-id must be owned by the calling user, and its own key must be
usable in the same way.
```

In `cmd/certificates/renew.go`, replace

```go
		if err := s.Authorize(); err != nil {
			return err
		}
		certService := s.Container.GetCertificateService()

		result, err := certService.RenewCertificate(s.Ctx, certID, s.Scope, validityDays)
```

with

```go
		if err := s.Authorize(); err != nil {
			return err
		}
		// Renewal re-signs with the certificate's key, so it needs keys/sign
		// like issuance does (B77).
		if err := s.RequireAlso(model.ActionKeysSign, model.OpSign); err != nil {
			return err
		}
		certService := s.Container.GetCertificateService()

		result, err := certService.RenewCertificate(s.Ctx, certID, s.Scope, validityDays)
```

and add a sentence to its `Long` text after the paragraph that states the renewal requirements: `Renewal also requires the Microsoft.KeyVault/vaults/keys/sign/action data action in the vault, because it signs with the certificate's key.`

- [ ] **Step 6: Run the tests and confirm they pass**

Run: `go test ./cmd/certificates/ ./api/`
Expected: PASS. `TestRenewCmd_Long*` help-text tests still pass (they assert other phrases).

- [ ] **Step 7: Commit**

Stage the files of this task, then invoke the `dev-workflow-skills:1-git-commit` skill via the Skill tool. Subject should say certificate create and renew require keys/sign on both HTTP and CLI (B77). No footer yet.

---

### Task 8: The scheduler re-checks the owner's keys/sign before renewing (B77)

**Files:**
- Modify: `internal/services/certificates/renewal_service.go:15-40` (type, config, struct, constructor), AutoRenew branch
- Modify: `internal/container/service_container.go:722-727` (renewal config), imports
- Modify: `internal/services/certificates/renewal_service_test.go` (helper, new tests, `SignAuthorizer` on the AutoRenew test)
- Modify: `internal/services/certificates/signing_key_lifecycle_test.go` (helper `allowSign` for package `certificates`)
- Modify: `internal/services/certificates/certificate_service_extended_test.go` (`TestCheckAndRenewCertificates_AutoRenewFailureSkipped`), `internal/services/certificates/ca_renewal_scheduler_test.go`
- Modify: `.claude/known-bugs.md` (new § B77)

**Interfaces:**
- Consumes: `authorization.RequireDataPlaneAccess` (Task 4).
- Produces: `type KeySignAuthorizer func(ctx context.Context, principalID, vaultID uuid.UUID) error` and field `RenewalServiceConfig.SignAuthorizer KeySignAuthorizer` in package `certificates`. A nil authorizer refuses every renewal.

- [ ] **Step 1: Write the failing tests**

In `internal/services/certificates/renewal_service_test.go`, add `"errors"` to the imports and append:

```go
// allowSign is a KeySignAuthorizer that grants every request.
func allowSign(context.Context, uuid.UUID, uuid.UUID) error { return nil }

// dueAutoRenewCert returns a certificate inside its renewal window with
// auto-renew on, in vaultID, owned by userID.
func dueAutoRenewCert(userID, vaultID uuid.UUID) model.Certificate {
	expires := time.Now().Add(10 * 24 * time.Hour)
	return model.Certificate{
		ID: uuid.New(), UserID: userID, VaultID: vaultID, Name: "due",
		CreatedAt: time.Now().Add(-365 * 24 * time.Hour), ExpiresAt: &expires,
		AutoRenew: true, RenewalDays: 30,
	}
}

// TestCheckAndRenewCertificates_RefusesWhenOwnerCannotSign is the scheduler
// half of B77: an owner who lost keys/sign in the vault gets no more
// unattended re-signing.
func TestCheckAndRenewCertificates_RefusesWhenOwnerCannotSign(t *testing.T) {
	userID, vaultID := uuid.New(), uuid.New()
	repo := &mockCertRepoForRenewal{}
	repo.On("ListAll", mock.Anything).Return([]model.Certificate{dueAutoRenewCert(userID, vaultID)}, nil)
	certSvc := &mockCertSvcForRenewal{}

	var gotPrincipal, gotVault uuid.UUID
	svc := certificates.NewCertificateRenewalService(certificates.RenewalServiceConfig{
		CertRepository:     repo,
		CertificateService: certSvc,
		Logger:             newTestLogger(),
		SignAuthorizer: func(_ context.Context, principalID, vaultID uuid.UUID) error {
			gotPrincipal, gotVault = principalID, vaultID
			return errors.New("forbidden: no role grants keys/sign in this vault")
		},
	})

	renewed, warned, err := svc.CheckAndRenewCertificates(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 0, renewed)
	assert.Equal(t, 0, warned)
	assert.Equal(t, userID, gotPrincipal)
	assert.Equal(t, vaultID, gotVault)
	certSvc.AssertNotCalled(t, "RenewCertificate", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
}

// TestCheckAndRenewCertificates_RefusesWithoutSignAuthorizer pins the fail-closed
// default: a scheduler wired without the check renews nothing.
func TestCheckAndRenewCertificates_RefusesWithoutSignAuthorizer(t *testing.T) {
	repo := &mockCertRepoForRenewal{}
	repo.On("ListAll", mock.Anything).Return([]model.Certificate{dueAutoRenewCert(uuid.New(), uuid.New())}, nil)
	certSvc := &mockCertSvcForRenewal{}

	svc := certificates.NewCertificateRenewalService(certificates.RenewalServiceConfig{
		CertRepository:     repo,
		CertificateService: certSvc,
		Logger:             newTestLogger(),
	})

	renewed, _, err := svc.CheckAndRenewCertificates(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 0, renewed)
	certSvc.AssertNotCalled(t, "RenewCertificate", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
}
```

In the same file, add `SignAuthorizer:     allowSign,` to the `RenewalServiceConfig` literal in `TestCheckAndRenewCertificates_AutoRenew`.

In `internal/services/certificates/signing_key_lifecycle_test.go` (package `certificates`), append:

```go
// allowSign is a KeySignAuthorizer that grants every request.
func allowSign(context.Context, uuid.UUID, uuid.UUID) error { return nil }
```

Add `SignAuthorizer:     allowSign,` to the `RenewalServiceConfig` literals in `TestCheckAndRenewCertificates_AutoRenewFailureSkipped` (`certificate_service_extended_test.go`) and `TestCheckAndRenewCertificates_CASignedKeepsIssuer` (`ca_renewal_scheduler_test.go`).

- [ ] **Step 2: Run the tests and confirm they fail**

Run: `go test ./internal/services/certificates/ -run TestCheckAndRenewCertificates -v`
Expected: FAIL at build time: `unknown field SignAuthorizer in struct literal of type certificates.RenewalServiceConfig`.

- [ ] **Step 3: Implement**

In `internal/services/certificates/renewal_service.go`, replace

```go
// RenewalServiceConfig holds dependencies for the renewal service.
type RenewalServiceConfig struct {
	CertRepository     repositories.CertificateRepositoryInterface
	CertificateService CertificateService
	Logger             *logging.Logger
}

type certRenewalService struct {
	certRepo repositories.CertificateRepositoryInterface
	certSvc  CertificateService
	logger   *logging.Logger
}

// NewCertificateRenewalService constructs the renewal service with the given configuration.
func NewCertificateRenewalService(cfg RenewalServiceConfig) CertificateRenewalService {
	return &certRenewalService{
		certRepo: cfg.CertRepository,
		certSvc:  cfg.CertificateService,
		logger:   cfg.Logger,
	}
}
```

with

```go
// KeySignAuthorizer returns nil when principalID may sign with keys in
// vaultID, and an error otherwise.
type KeySignAuthorizer func(ctx context.Context, principalID, vaultID uuid.UUID) error

// RenewalServiceConfig holds dependencies for the renewal service.
type RenewalServiceConfig struct {
	CertRepository     repositories.CertificateRepositoryInterface
	CertificateService CertificateService
	Logger             *logging.Logger
	// SignAuthorizer re-checks, before every unattended renewal, that the
	// certificate's owner may still sign with keys in its vault (B77). Nil
	// refuses every renewal rather than skipping the check.
	SignAuthorizer KeySignAuthorizer
}

type certRenewalService struct {
	certRepo  repositories.CertificateRepositoryInterface
	certSvc   CertificateService
	logger    *logging.Logger
	signAuthz KeySignAuthorizer
}

// NewCertificateRenewalService constructs the renewal service with the given configuration.
func NewCertificateRenewalService(cfg RenewalServiceConfig) CertificateRenewalService {
	return &certRenewalService{
		certRepo:  cfg.CertRepository,
		certSvc:   cfg.CertificateService,
		logger:    cfg.Logger,
		signAuthz: cfg.SignAuthorizer,
	}
}
```

In `CheckAndRenewCertificates`, replace

```go
			// The renewal is scoped to the certificate's own vault, so its key
			// and CA links are only followed inside that vault (B76).
			_, err := s.certSvc.RenewCertificate(ctx, cert.ID, model.NewVaultScope(cert.VaultID, cert.UserID), validityDays)
```

with

```go
			// Renewal re-signs with the certificate's key on its owner's
			// behalf, so the owner must still hold keys/sign in the vault
			// (B77). A scheduler wired without the check renews nothing.
			if s.signAuthz == nil {
				s.logger.LogAuditError(cert.UserID.String(), "cert_auto_renew", "failed",
					"Auto-renewal refused, no sign authorizer is configured: "+cert.Name, nil)
				continue
			}
			if authzErr := s.signAuthz(ctx, cert.UserID, cert.VaultID); authzErr != nil {
				s.logger.LogAuditError(cert.UserID.String(), "cert_auto_renew", "denied",
					"Auto-renewal refused, owner may not sign with keys in this vault: "+cert.Name, authzErr)
				continue
			}

			// The renewal is scoped to the certificate's own vault, so its key
			// and CA links are only followed inside that vault (B76).
			_, err := s.certSvc.RenewCertificate(ctx, cert.ID, model.NewVaultScope(cert.VaultID, cert.UserID), validityDays)
```

In `internal/container/service_container.go`, add `"github.com/google/uuid"` and `"rocketvault/model"` to the imports (neither is imported today), and replace

```go
	c.certRenewalService = certServices.NewCertificateRenewalService(certServices.RenewalServiceConfig{
		CertRepository:     c.certificateRepository,
		CertificateService: c.certificateService,
		Logger:             c.logger,
	})
```

with

```go
	c.certRenewalService = certServices.NewCertificateRenewalService(certServices.RenewalServiceConfig{
		CertRepository:     c.certificateRepository,
		CertificateService: c.certificateService,
		Logger:             c.logger,
		// The same two-stage check the CLI and HTTP handlers run for
		// keys/sign, applied to the certificate's owner (B77).
		SignAuthorizer: func(ctx context.Context, principalID, vaultID uuid.UUID) error {
			return authzServices.RequireDataPlaneAccess(ctx, c.accessPolicyService, c.roleAssignmentService,
				principalID, vaultID, model.PolicyResourceKeys, model.OpSign, model.ActionKeysSign)
		},
	})
```

- [ ] **Step 4: Run the tests and confirm they pass**

Run: `go build ./... && go test ./internal/services/certificates/ ./internal/container/`
Expected: PASS.

- [ ] **Step 5: Add the known-bugs entry**

In `.claude/known-bugs.md`, insert immediately before the line `## Deferred Refactors`:

```markdown
### B77 — Certificate create and renew ignored key lifecycle and did not require the sign action

**Status**: Fixed 2026-09-30 (GitHub issue #43)
**Severity**: Medium — a revoked, disabled or expired key kept issuing and
renewing certificates, and `certificates/create` alone was enough to sign
with a key
**Files**: `internal/services/certificates/certificate_service.go`,
`internal/services/certificates/renewal_service.go`,
`internal/services/authorization/data_action_authz.go`,
`cmd/vaultcli/session.go`, `cmd/vaultcli/vault.go`, `api/certificates.go`,
`cmd/certificates/create.go`, `cmd/certificates/renew.go`,
`internal/container/service_container.go`

**Symptom**: `ValidateKeyOwnership` and the key re-read after it never looked
at `Revoked`, `Enabled` or the validity window, so a key the crypto path
refused (`loadAndAuthorize`) still minted and renewed certificates. Creating
a certificate needed only `certificates/create` and ownership of the key;
`keys/sign` was never required and a deny policy on key sign was never
consulted. The scheduler kept re-signing unattended, under an admin scope
(B76), for owners who had since lost access. A certificate row stores a copy
of its key's private PEM, used as the CA signing key when that certificate
is a CA, so revoking the key did not stop the CA either.

**Root cause**: authorization for issuance lived only in the route's single
data action, and lifecycle lived only in the key crypto service.

**What was fixed**:

- `ValidateKeyOwnership` refuses a revoked or inaccessible key with
  `ErrSigningKeyUnusable`; create (both paths) and renew call it.
- `requireCAKeyUsable` refuses to sign through a CA whose linked key is
  unusable or unreadable in scope, or which records no key at all.
- `authorization.RequireDataPlaneAccess` is the one two-stage check (deny
  policy, then role grant). `createCertificate` calls it for
  `(keys, sign, keys/sign/action)`; the CLI `certificate create` and
  `certificate renew` call it through `vaultcli.Session.RequireAlso`; the
  scheduler calls it for the certificate's owner through
  `RenewalServiceConfig.SignAuthorizer`, and refuses everything when that is
  unset. There is no HTTP renew route.

**Decision — what revoking a key does to certificates that embed it**: the
key can no longer issue or renew anything, as a leaf key or through a CA
row's embedded copy. Certificates already issued are left alone: not
revoked, disabled or deleted, since a key operation cascading into other
objects would be destructive and Azure does not do it either; X.509
revocation is its own concern. The embedded PEM is not erased at rest; no
code path uses it once the linked key is unusable, and no API returns it.
A CA row with no key link is refused as a signer. Every CA that passes
`inspectCertificateCA` was issued after `key_id` existed (B43 came later),
so such a row can only be one whose link was dropped at restore (B76).

**Accepted behavior change**: Key Vault Certificates Officer alone no longer
issues certificates; the caller also needs a role granting `keys/sign`, such
as Key Vault Crypto User. Auto-renewal likewise stops for owners without it.

**Pinned by**: `TestValidateKeyOwnership_RefusesUnusableKey`,
`TestCreateSelfSignedCertificate_RefusesRevokedKey`,
`TestRenewCertificate_RefusesDisabledKey`, `TestRequireCAKeyUsable`,
`TestCreateCASignedCertificate_RefusesCAWithRevokedKey`
(`internal/services/certificates/signing_key_lifecycle_test.go`);
`TestRenewCertificate_RevokedCAKeyRefusesRenewal` (`ca_renewal_test.go`);
`TestRequireDataPlaneAccess_*`
(`internal/services/authorization/data_plane_access_test.go`);
`TestCreateCertificate_RequiresKeySign`,
`TestCreateCertificate_KeySignDenyPolicyRefuses` (`api/certificates_test.go`);
`TestCertCreateCmd_RequiresKeySign`, `TestCertRenewCmd_RequiresKeySign`
(`cmd/certificates/certs_cmd_test.go`);
`TestCheckAndRenewCertificates_RefusesWhenOwnerCannotSign`,
`TestCheckAndRenewCertificates_RefusesWithoutSignAuthorizer`
(`renewal_service_test.go`).

---
```

- [ ] **Step 6: Commit**

Stage the files of this task, then invoke the `dev-workflow-skills:1-git-commit` skill via the Skill tool. Subject should say the renewal scheduler re-checks the owner's keys/sign before renewing (B77). Footer: `Fixes #43`.

---

### Task 9: Certificate-creation errors map to 403/404 instead of 500 (B78)

**Files:**
- Modify: `internal/services/certificates/certificate_service.go` (sentinels after `ErrSigningKeyUnusable`; `ValidateCertificateAccess` return at `:1046`; `ValidateKeyOwnership` returns at `:1084`, `:1089`)
- Modify: `api/errors_certificate.go:18-31`
- Modify: `api/certificates.go` (`createCertificate` error branch)
- Test: `internal/services/certificates/signing_key_lifecycle_test.go`, `api/certificates_test.go`

**Interfaces:**
- Consumes: `ErrSigningKeyUnusable` (Task 5).
- Produces in package `certificates`: `ErrSigningKeyForbidden` (text `forbidden: cannot use other users' keys`), `ErrCACertForbidden` (text `forbidden: cannot access other users' certificates`), `ErrSigningKeyNotFound` (text `key not found`). Message text of every existing error is unchanged.

- [ ] **Step 1: Write the failing tests**

Append to `internal/services/certificates/signing_key_lifecycle_test.go`:

```go
// TestValidators_ReturnSentinels lets the HTTP layer map these refusals by
// identity instead of reporting them as server faults (B78).
func TestValidators_ReturnSentinels(t *testing.T) {
	t.Parallel()

	ownerID, callerID, vaultID := uuid.New(), uuid.New(), uuid.New()
	scope := model.NewVaultScope(vaultID, callerID)

	keyID := uuid.New()
	keyRepo := &mockKeyRepo{}
	vaultScopedKeyRepo(keyRepo, keyID, vaultID, &model.Key{ID: keyID, UserID: ownerID, VaultID: vaultID, Enabled: true})
	svc := newCertSvc(&mockCertRepository{}, keyRepo)
	require.ErrorIs(t, svc.ValidateKeyOwnership(context.Background(), keyID, scope), ErrSigningKeyForbidden)

	missing := uuid.New()
	missingRepo := &mockKeyRepo{}
	missingRepo.On("Read", mock.Anything, missing, scope).Return(nil, errors.New("key not found or access denied"))
	svc = newCertSvc(&mockCertRepository{}, missingRepo)
	err := svc.ValidateKeyOwnership(context.Background(), missing, scope)
	require.ErrorIs(t, err, ErrSigningKeyNotFound)
	require.Equal(t, "key not found: key not found or access denied", err.Error())

	caID := uuid.New()
	certRepo := &mockCertRepository{}
	certRepo.On("Read", mock.Anything, caID, scope).Return(&model.Certificate{ID: caID, UserID: ownerID, VaultID: vaultID}, nil)
	svc = newCertSvc(certRepo, &mockKeyRepo{})
	require.ErrorIs(t, svc.ValidateCertificateAccess(context.Background(), caID, scope), ErrCACertForbidden)
}
```

Append to `api/certificates_test.go`:

```go
// TestCreateCertificate_MapsSigningKeyErrors pins B78: a refusal about the
// caller's key or CA is a client problem, not a 500.
func TestCreateCertificate_MapsSigningKeyErrors(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want int
	}{
		{"foreign key", certServices.ErrSigningKeyForbidden, http.StatusForbidden},
		{"foreign CA", fmt.Errorf("cannot access CA certificate: %w", certServices.ErrCACertForbidden), http.StatusForbidden},
		{"unusable key", fmt.Errorf("%w: %s", certServices.ErrSigningKeyUnusable, uuid.New()), http.StatusForbidden},
		{"missing key", fmt.Errorf("%w: %w", certServices.ErrSigningKeyNotFound, errors.New("key not found or access denied")), http.StatusNotFound},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			svc := &mockCertService{}
			svc.On("CreateSelfSignedCertificate", mock.Anything, mock.Anything).Return(nil, tc.err)

			c := newCertCtx(svc, certAdminClaims())
			w := httptest.NewRecorder()
			body, _ := json.Marshal(map[string]any{
				"name": "mycert", "key_id": uuid.New().String(), "validity_days": 365,
			})
			r := httptest.NewRequest(http.MethodPost, "/certificates", bytes.NewReader(body))

			createCertificate(c, w, r)
			if c.Err != nil {
				writeError(w, c)
			}

			assert.Equal(t, tc.want, w.Code)
		})
	}
}
```

- [ ] **Step 2: Run the tests and confirm they fail**

Run: `go test ./internal/services/certificates/ ./api/ -run 'ReturnSentinels|MapsSigningKeyErrors' -v`
Expected: FAIL at build time: `undefined: ErrSigningKeyForbidden` (and the other two sentinels).

- [ ] **Step 3: Implement**

In `certificate_service.go`, after `ErrSigningKeyUnusable`, add:

```go
// ErrSigningKeyForbidden is returned when the signing key belongs to another
// user. Its text is the message this refusal always had.
var ErrSigningKeyForbidden = errors.New("forbidden: cannot use other users' keys")

// ErrCACertForbidden is returned when the signing CA certificate belongs to
// another user. Its text is the message this refusal always had.
var ErrCACertForbidden = errors.New("forbidden: cannot access other users' certificates")

// ErrSigningKeyNotFound is returned when the signing key does not resolve in
// the caller's vault scope.
var ErrSigningKeyNotFound = errors.New("key not found")
```

In `ValidateCertificateAccess`, replace `return fmt.Errorf("forbidden: cannot access other users' certificates")` with `return ErrCACertForbidden`.

In `ValidateKeyOwnership`, replace `return fmt.Errorf("key not found: %w", err)` with `return fmt.Errorf("%w: %w", ErrSigningKeyNotFound, err)`, and replace `return fmt.Errorf("forbidden: cannot use other users' keys")` with `return ErrSigningKeyForbidden`.

In `api/errors_certificate.go`, bring the `switch` in `writeCertificateError` to the following. The four arms under the B78 comment are this plan's. If the secrets plan (B82) has already landed, its `case errors.Is(err, repositories.ErrNameTaken):` arm is already in the switch, so keep it (before `default:`) and add only this plan's arms; if this plan lands first, B82 adds its arm afterwards. Never drop the other plan's arm:

```go
	switch {
	case errors.Is(err, certServices.ErrCertLifecycleDenied):
		c.SetPermissionError("certificate is disabled or outside its valid time window")
	case errors.Is(err, certServices.ErrCertNotFound):
		c.SetNotFound("certificate")
	case errors.Is(err, model.ErrCertPurgeProtected):
		c.SetPermissionError(purgeProtectedMessage("certificate"))
	case errors.Is(err, model.ErrGlobalPurgeProtectionEnabled):
		c.SetPermissionError(err.Error())
	// B78: refusals about the caller's signing key or CA are client problems.
	// Each uses a fixed message, so no wrapped repository text reaches the
	// response.
	case errors.Is(err, certServices.ErrSigningKeyForbidden):
		c.SetPermissionError("the signing key belongs to another user")
	case errors.Is(err, certServices.ErrCACertForbidden):
		c.SetPermissionError("the CA certificate belongs to another user")
	case errors.Is(err, certServices.ErrSigningKeyUnusable):
		c.SetPermissionError("signing key is revoked, disabled or outside its valid time window")
	case errors.Is(err, certServices.ErrSigningKeyNotFound):
		c.SetNotFound("key")
	default:
		c.SetInternalError(err)
	}
```

In `api/certificates.go`, `createCertificate`, replace

```go
	if err != nil {
		c.SetInternalError(err)
		return
	}

	// Resolve enabled value shown in the response.
```

with

```go
	if err != nil {
		writeCertificateError(c, err)
		return
	}

	// Resolve enabled value shown in the response.
```

- [ ] **Step 4: Run the tests and confirm they pass**

Run: `go test ./internal/services/certificates/ ./api/ ./cmd/certificates/`
Expected: PASS. `TestCreateCertificate_ServiceError_Returns500` still sees 500 (its plain `errors.New("key not found")` wraps no sentinel), and the existing `Contains(err.Error(), "forbidden")` / `"key not found"` assertions still match.

- [ ] **Step 5: Commit**

Stage the files of this task, then invoke the `dev-workflow-skills:1-git-commit` skill via the Skill tool. Subject should say certificate creation maps signing-key refusals to 403/404 instead of 500 (B78). No footer yet.

---

### Task 10: Cap validity_days (B78)

**Files:**
- Modify: `model/certificate.go` (constant after the `Certificate` struct)
- Modify: `internal/validation/certificate_validation.go:5-24`
- Modify: `api/certificates.go:151-154` (`ValidateCertificateCreate` call)
- Modify: `internal/services/certificates/certificate_service.go` (sentinel; guards after the three `validity days must be positive` blocks at `:223-226`, `:361-364`, `:892-895`)
- Modify: `api/errors_certificate.go` (one more case)
- Test: `internal/validation/validation_test.go`, `internal/services/certificates/signing_key_lifecycle_test.go`, `api/certificates_test.go`
- Modify: `.claude/known-bugs.md` (new § B78)

**Interfaces:**
- Consumes: nothing new.
- Produces: `model.MaxCertificateValidityDays = 36500`; field `ValidityDays int` on `validation.CertificateCreateRequest`; `certificates.ErrInvalidValidityDays`.

- [ ] **Step 1: Write the failing tests**

Append to `internal/validation/validation_test.go`:

```go
// TestValidateCertificateCreate_ValidityDaysUpperBound pins B78. Without a
// cap, a huge value pushes NotAfter past X.509's four-digit year and the
// request fails deep inside certificate generation as a 500.
func TestValidateCertificateCreate_ValidityDaysUpperBound(t *testing.T) {
	t.Parallel()

	ok := ValidateCertificateCreate(CertificateCreateRequest{Name: "cert", ValidityDays: model.MaxCertificateValidityDays})
	assert.NoError(t, ok, "the maximum itself is allowed")

	tooLong := ValidateCertificateCreate(CertificateCreateRequest{Name: "cert", ValidityDays: model.MaxCertificateValidityDays + 1})
	assert.Error(t, tooLong)
}
```

Append to `internal/services/certificates/signing_key_lifecycle_test.go`:

```go
// TestValidityDaysUpperBound_ServiceSide covers the CLI, which calls the
// service directly and never sees the HTTP validation (B78).
func TestValidityDaysUpperBound_ServiceSide(t *testing.T) {
	t.Parallel()

	userID, vaultID, certID := uuid.New(), uuid.New(), uuid.New()
	svc := newCertSvc(&mockCertRepository{}, &mockKeyRepo{})
	_, err := svc.CreateSelfSignedCertificate(context.Background(), CreateCertificateRequest{
		Name: "c", KeyID: uuid.New(), ValidityDays: model.MaxCertificateValidityDays + 1, UserID: userID, VaultID: vaultID,
	})
	require.ErrorIs(t, err, ErrInvalidValidityDays)

	caID := uuid.New()
	_, err = svc.CreateCASignedCertificate(context.Background(), CreateCertificateRequest{
		Name: "c", KeyID: uuid.New(), ValidityDays: model.MaxCertificateValidityDays + 1, UserID: userID, VaultID: vaultID, CACertID: &caID,
	})
	require.ErrorIs(t, err, ErrInvalidValidityDays)

	scope := model.NewVaultScope(vaultID, userID)
	certRepo := &mockCertRepository{}
	certRepo.On("Read", mock.Anything, certID, scope).Return(&model.Certificate{
		ID: certID, UserID: userID, VaultID: vaultID, KeyID: uuid.New(), Name: "c", Enabled: true,
	}, nil)
	svc = newCertSvc(certRepo, &mockKeyRepo{})
	_, err = svc.RenewCertificate(context.Background(), certID, scope, model.MaxCertificateValidityDays+1)
	require.ErrorIs(t, err, ErrInvalidValidityDays)
}
```

Append to `api/certificates_test.go`:

```go
func TestCreateCertificate_ValidityAboveMaximum_Returns400(t *testing.T) {
	svc := &mockCertService{}
	c := newCertCtx(svc, certAdminClaims())
	w := httptest.NewRecorder()
	body, _ := json.Marshal(map[string]any{
		"name": "mycert", "key_id": uuid.New().String(), "validity_days": model.MaxCertificateValidityDays + 1,
	})
	r := httptest.NewRequest(http.MethodPost, "/certificates", bytes.NewReader(body))

	createCertificate(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusBadRequest, w.Code)
	svc.AssertNotCalled(t, "CreateSelfSignedCertificate", mock.Anything, mock.Anything)
}
```

- [ ] **Step 2: Run the tests and confirm they fail**

Run: `go test ./internal/validation/ ./internal/services/certificates/ ./api/ -run 'ValidityDaysUpperBound|ValidityAboveMaximum' -v`
Expected: FAIL at build time: `undefined: model.MaxCertificateValidityDays`, `unknown field ValidityDays`, `undefined: ErrInvalidValidityDays`.

- [ ] **Step 3: Implement**

In `model/certificate.go`, after the `Certificate` struct, add:

```go
// MaxCertificateValidityDays caps a certificate's validity period. It is 100
// years: longer than any real root CA, and short enough that NotAfter stays
// far inside X.509's four-digit-year GeneralizedTime range (B78).
const MaxCertificateValidityDays = 36500
```

Replace the whole of `internal/validation/certificate_validation.go` with:

```go
package validation

import (
	validation "github.com/go-ozzo/ozzo-validation/v4"

	"rocketvault/model"
)

// CertificateCreateRequest is the input for creating a certificate.
type CertificateCreateRequest struct {
	Name         string
	Tags         []string
	ValidityDays int
}

// ValidateCertificateCreate validates certificate creation input. A
// non-positive ValidityDays is rejected by the caller before this runs;
// validation.Max skips the zero value, so it only enforces the cap (B78).
func ValidateCertificateCreate(req CertificateCreateRequest) error {
	return validation.ValidateStruct(&req,
		validation.Field(&req.Name,
			validation.Required,
			validation.Length(1, 127),
			CertificateNameRule(),
		),
		validation.Field(&req.Tags,
			validation.Length(0, 15),
			validation.Each(validation.Length(1, 256)),
		),
		validation.Field(&req.ValidityDays,
			validation.Max(model.MaxCertificateValidityDays),
		),
	)
}

// CertificateNameRule validates certificate names.
func CertificateNameRule() validation.Rule {
	return validation.Match(CertificateNamePattern).Error("must contain only alphanumeric characters and hyphens, and start with a letter")
}
```

In `api/certificates.go`, replace

```go
	if err := vvalidation.ValidateCertificateCreate(vvalidation.CertificateCreateRequest{
		Name: req.Name,
		Tags: req.Tags,
	}); err != nil {
```

with

```go
	if err := vvalidation.ValidateCertificateCreate(vvalidation.CertificateCreateRequest{
		Name:         req.Name,
		Tags:         req.Tags,
		ValidityDays: req.ValidityDays,
	}); err != nil {
```

In `certificate_service.go`, add after `ErrSigningKeyNotFound`:

```go
// ErrInvalidValidityDays is returned when a validity period exceeds
// model.MaxCertificateValidityDays (B78).
var ErrInvalidValidityDays = errors.New("invalid validity days")
```

In `CreateSelfSignedCertificate`, replace

```go
		s.logger.LogAuditError(req.UserID.String(), "create_self_signed_cert", "failed", "validity days must be positive", nil)
		return nil, fmt.Errorf("validity days must be positive")
	}
```

with

```go
		s.logger.LogAuditError(req.UserID.String(), "create_self_signed_cert", "failed", "validity days must be positive", nil)
		return nil, fmt.Errorf("validity days must be positive")
	}
	if req.ValidityDays > model.MaxCertificateValidityDays {
		s.logger.LogAuditError(req.UserID.String(), "create_self_signed_cert", "failed", "validity days exceed the maximum", nil)
		return nil, fmt.Errorf("%w: must not exceed %d", ErrInvalidValidityDays, model.MaxCertificateValidityDays)
	}
```

In `CreateCASignedCertificate`, replace

```go
		s.logger.LogAuditError(req.UserID.String(), "create_ca_signed_cert", "failed", "validity days must be positive", nil)
		return nil, fmt.Errorf("validity days must be positive")
	}
```

with

```go
		s.logger.LogAuditError(req.UserID.String(), "create_ca_signed_cert", "failed", "validity days must be positive", nil)
		return nil, fmt.Errorf("validity days must be positive")
	}
	if req.ValidityDays > model.MaxCertificateValidityDays {
		s.logger.LogAuditError(req.UserID.String(), "create_ca_signed_cert", "failed", "validity days exceed the maximum", nil)
		return nil, fmt.Errorf("%w: must not exceed %d", ErrInvalidValidityDays, model.MaxCertificateValidityDays)
	}
```

In `RenewCertificate`, replace

```go
		s.logger.LogAuditError(userID.String(), "renew_certificate", "failed", "validity days must be positive", nil)
		return nil, fmt.Errorf("validity days must be positive")
	}
```

with

```go
		s.logger.LogAuditError(userID.String(), "renew_certificate", "failed", "validity days must be positive", nil)
		return nil, fmt.Errorf("validity days must be positive")
	}
	if validityDays > model.MaxCertificateValidityDays {
		s.logger.LogAuditError(userID.String(), "renew_certificate", "failed", "validity days exceed the maximum", nil)
		return nil, fmt.Errorf("%w: must not exceed %d", ErrInvalidValidityDays, model.MaxCertificateValidityDays)
	}
```

In `api/errors_certificate.go`, merge this arm into the same `switch` before `default:`, alongside the Task 9 arms and any `ErrNameTaken` arm from the secrets plan (B82):

```go
	case errors.Is(err, certServices.ErrInvalidValidityDays):
		c.SetInvalidParam("validity_days")
```

- [ ] **Step 4: Run the tests and confirm they pass**

Run: `go test ./internal/validation/ ./internal/services/certificates/ ./api/ ./cmd/certificates/`
Expected: PASS.

- [ ] **Step 5: File the GitHub issue and add the known-bugs entry**

```bash
gh issue create --label bug \
  --title "B78: Certificate creation maps signing-key refusals to 500 and accepts unbounded validity_days" \
  --body "$(cat <<'EOF'
**Severity**: Low

**Files**: `api/certificates.go` (createCertificate error branch, validity check), `api/errors_certificate.go`, `internal/validation/certificate_validation.go`, `internal/services/certificates/certificate_service.go`

**Symptom**: `createCertificate` reported every service error with `SetInternalError`, so "forbidden: cannot use other users' keys", a foreign CA certificate, and a missing key all returned 500. `validity_days` had only a lower bound; a very large value pushed NotAfter past X.509's four-digit year and failed inside certificate generation, also as a 500. The CLI had no bound either.

**Root cause**: the handler never used `writeCertificateError`, and the validators returned string errors with no sentinel to map. No layer capped the validity period.

Full detail: .claude/known-bugs.md § B78
EOF
)"
```

Note the printed issue number as `<M>`. In `.claude/known-bugs.md`, insert immediately before the line `## Deferred Refactors`:

```markdown
### B78 — Certificate creation mapped signing-key refusals to 500 and accepted unbounded `validity_days`

**Status**: Fixed 2026-09-30 (GitHub issue #<M>)
**Severity**: Low — wrong status codes and a server fault for bad input; no
access was granted
**Files**: `api/certificates.go`, `api/errors_certificate.go`,
`internal/validation/certificate_validation.go`,
`internal/services/certificates/certificate_service.go`, `model/certificate.go`

**Symptom**: `createCertificate` reported every service error with
`SetInternalError`, so a key owned by someone else, a CA certificate owned by
someone else, and a key missing from the vault all came back as 500.
`validity_days` had a lower bound only; a very large value pushed NotAfter
past X.509's four-digit year and failed inside certificate generation, again
as a 500. The CLI, which calls the service directly, had no bound at all.

**Root cause**: the handler never used `writeCertificateError`, and the
validators returned bare string errors with nothing to map by identity.
Nothing capped the validity period.

**What was fixed**: `ErrSigningKeyForbidden`, `ErrCACertForbidden` and
`ErrSigningKeyNotFound` carry the exact messages those refusals always had;
`writeCertificateError` maps them, and `ErrSigningKeyUnusable` (B77), to
403/404 with fixed response text; `createCertificate` uses it.
`model.MaxCertificateValidityDays` (36500) is enforced in
`ValidateCertificateCreate` for HTTP and in the three service entry points
for the CLI, as `ErrInvalidValidityDays`, mapped to 400.

**Accepted limitation**: a CA certificate that does not resolve in scope on
the CA-signed create path still returns 500 (`certificate not found: ...` is
not wrapped in `ErrCertNotFound`). The generic-500 text leak is B82's scope
(`docs/superpowers/plans/2026-09-30-secrets-and-error-responses.md`).

**Pinned by**: `TestValidators_ReturnSentinels`,
`TestValidityDaysUpperBound_ServiceSide`
(`internal/services/certificates/signing_key_lifecycle_test.go`);
`TestCreateCertificate_MapsSigningKeyErrors`,
`TestCreateCertificate_ValidityAboveMaximum_Returns400`
(`api/certificates_test.go`);
`TestValidateCertificateCreate_ValidityDaysUpperBound`
(`internal/validation/validation_test.go`).

---
```

Replace `<M>` with the issue number printed above.

- [ ] **Step 6: Commit**

Stage only this task's files, then invoke the `dev-workflow-skills:1-git-commit` skill via the Skill tool. Subject should say certificate validity is capped at 36500 days on HTTP and CLI (B78). Footer: `Fixes #<M>`.

---

### Task 11: Release note and final verification

**Files:**
- Create: `docs/release-notes/v4.8.0-certificate-restore-renewal-isolation.md`
- Modify: `scripts/docsgen/docs.go:45` (add the note after the v4.6.0 line; if other v4.6.1/v4.7.0 notes have landed first, add it after the last release-note line)

**Interfaces:**
- Consumes: the behavior changes of Tasks 1-10.
- Produces: operator-facing upgrade guidance.

- [ ] **Step 1: Write the release note**

Create `docs/release-notes/v4.8.0-certificate-restore-renewal-isolation.md`:

```markdown
# v4.8.0 — Certificate restore and renewal isolation

This release closes a High-severity cross-vault path through certificate
backup and auto-renewal (`.claude/known-bugs.md` § B76), makes certificate
issuance respect the signing key's lifecycle and the `keys/sign` data action
(§ B77, GitHub #43), and fixes two certificate-creation input and status-code
defects (§ B78). Full implementation plan:
`docs/superpowers/plans/2026-09-30-certificate-restore-renewal-isolation.md`.

## The breaking changes

1. **Per-item backup blobs are sealed, and old blobs no longer restore.**
   `POST .../secrets/{id}/backup`, `.../keys/{id}/backup` and
   `.../certificates/{id}/backup` now return a blob that starts with `rvb2.`
   and is AES-256-GCM encrypted and authenticated under a key derived from
   the master key. `.../restore` refuses, with 400, any blob taken before
   this upgrade, any modified blob, and any blob sealed under a different
   master key. There is no switch to accept old blobs: an old blob and a
   hand-forged one look identical, and accepting either is the vulnerability
   this release closes. Blobs never survived a master-key rotation anyway,
   because the values inside them were already master-key ciphertext.
2. **Issuing or renewing a certificate needs `keys/sign`.** Besides
   `Microsoft.KeyVault/vaults/certificates/create`, the caller must hold
   `Microsoft.KeyVault/vaults/keys/sign/action` in the vault, and a deny
   policy on `(keys, sign)` now blocks issuance. This applies to
   `POST .../certificates`, `rocketvault certificate create` and
   `rocketvault certificate renew`. **Key Vault Certificates Officer alone is
   no longer enough**; pair it with Key Vault Crypto User (or use Key Vault
   Crypto Officer or Key Vault Administrator).
3. **Auto-renewal re-checks the owner.** The scheduler renews a certificate
   only while its owner still holds `keys/sign` in the certificate's vault,
   and it renews under that vault's scope. Certificates whose owners lack it
   stop renewing and log `cert_auto_renew` / `denied` in the audit log.
4. **Unusable keys cannot sign.** A revoked, disabled, expired or
   not-yet-active key can no longer issue or renew a certificate. A CA
   certificate can no longer sign while its own linked key is in that state,
   or when it records no key at all. Certificates already issued are not
   touched.
5. **Restored certificates may lose their key and CA links.** A certificate
   restored into a vault where its key or signing CA does not exist keeps
   its body and private key but loses those links, so it will not renew
   there. Restores into the vault the backup came from are unaffected.
6. **`validity_days` is capped at 36500** on create (HTTP 400) and on CLI
   create and renew.
7. **Status codes.** Certificate creation now answers 403 for a key or CA
   owned by someone else or an unusable key, and 404 for a key that is not in
   the vault, instead of 500.

## Upgrade procedure

1. Before upgrading, note which items you rely on per-item backups for. After
   upgrading, take fresh backups of them; keep the old blobs only as a
   record, since they will not restore.
2. List who issues certificates:
   `rocketvault vault-access list --vault <name>`. Grant every principal
   that holds only Key Vault Certificates Officer the Key Vault Crypto User
   role in the same vault:
   `rocketvault vault-access grant <user> --role "Key Vault Crypto User" --vault <name>`.
3. Check the audit log after the first scheduler run for `cert_auto_renew`
   rows with status `denied` or `failed`; each names the certificate that
   stopped renewing and why.
4. A CA certificate that now refuses to sign with "records no signing key"
   was restored from another vault or created before `key_id` existed.
   Re-issue it with `rocketvault certificate create --is-ca` over a key in
   the same vault.

## What did not change

- Existing certificates, keys, secrets and their data are not modified by
  the upgrade. No schema migration runs.
- The owner comparison on the signing key and CA certificate (B32) is
  unchanged.
- Full-database backup (`rocketvault backup`) is unaffected; only per-item
  blobs are sealed.
```

The two `vault-access` commands match `cmd/vault-access/grant.go:58-80` (`grant <principal> --role ... --vault ...`) and `list.go:37` (`list --vault ...`).

In `scripts/docsgen/docs.go`, add after the last release-note entry:

```go
	{"docs/release-notes/v4.8.0-certificate-restore-renewal-isolation.md", "docs/release-notes/v4.8.0-certificate-restore-renewal-isolation.html"},
```

- [ ] **Step 2: Build the docs**

Run: `./scripts/docs.sh build`
Expected: exits 0 and writes `docs/release-notes/v4.8.0-certificate-restore-renewal-isolation.html`.

- [ ] **Step 3: Full verification**

Run: `go build ./... && go vet ./... && go test ./...`
Expected: all PASS. Lint (`golangci-lint run`) must run in CI or on a fixed toolchain; it fails locally because of the snap Go toolchain.

Run: `grep -rn "NewAdminScope" internal/services/certificates/ --include='*.go' | grep -v _test`
Expected: no output.

- [ ] **Step 4: Commit**

Stage the release note, its generated HTML, and `scripts/docsgen/docs.go`, then invoke the `dev-workflow-skills:1-git-commit` skill via the Skill tool. Subject should say the release note for certificate restore and renewal isolation is added.

---

## Self-Review

**Spec coverage.**
- B76 restore: sealing (Task 2), reference verification with a clear-not-reject decision (Task 3), vault-scoped scheduler (Task 1), HSM-handle decision (Task 2 test `TestRestoreKey_RejectsForgedHSMHandle`, § B76 text), pre-upgrade blob decision with a version marker `rvb2.` (Task 2, § B76, release note).
- B77 / #43: lifecycle on create and renew (Task 5), sign data action and sign policy operation on HTTP create, CLI create and CLI renew with one shared helper (Tasks 4, 7), scheduler re-check (Task 8), revocation decision with the minimal safe part implemented (Task 6).
- B78: error mapping (Task 9), validity cap on HTTP and CLI (Task 10).
- Release note for behavior changes (Task 11); known-bugs entries B76 (Task 3), B77 (Task 8), B78 (Task 10); issue footers `Fixes #<N>`, `Fixes #43`, `Fixes #<M>`.

**Placeholder scan.** `<N>` and `<M>` are GitHub issue numbers that only exist once `gh issue create` runs in the same step; each step says where they come from. Fixture sweeps in Tasks 5 and 6 list the verified locations and the exact edit pattern. No TBD or TODO markers remain.

**Type consistency.**
- `ErrSigningKeyUnusable`, `ErrSigningKeyForbidden`, `ErrCACertForbidden`, `ErrSigningKeyNotFound`, `ErrInvalidValidityDays` are all `error` vars in package `certificates`, referenced as `certServices.X` in `api/`.
- `RequireDataPlaneAccess(ctx, policies AccessPolicyService, roles RoleAssignmentService, principalID, vaultID uuid.UUID, resourceType model.PolicyResourceType, op model.PolicyOperation, action model.DataAction) error` is called identically in `cmd/vaultcli/vault.go`, `cmd/vaultcli/session.go`, `api/certificates.go` and the container's `SignAuthorizer`.
- `KeySignAuthorizer func(ctx context.Context, principalID, vaultID uuid.UUID) error` matches the `allowSign` helpers in both test packages and the container closure.
- `SetSealKey(masterKey []byte) error` is called with `[]byte` from `common.ParseMasterKey` and from the test helpers.
- `model.NewVaultScope(cert.VaultID, cert.UserID)` in Task 1 matches the mock expectations `model.NewVaultScope(vaultID, userID)` in the updated scheduler tests.
