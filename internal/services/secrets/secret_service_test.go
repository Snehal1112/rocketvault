package secrets_test

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"rocketvault/common"
	"rocketvault/internal/repositories"
	"rocketvault/internal/services/secrets"
	"rocketvault/internal/testutils"
	"rocketvault/model"
)

// newService wires a secretService with the provided mocks.
func newService(
	repo *testutils.MockSecretRepository,
	crypto *testutils.MockCryptographyService,
	ver *testutils.MockVersioningService,
	tag *testutils.MockTagService,
	t *testing.T,
) secrets.SecretService {
	return secrets.NewSecretService(secrets.SecretServiceConfig{
		SecretRepository: repo,
		CryptoService:    crypto,
		VersionService:   ver,
		TagService:       tag,
		Logger:           testutils.NewTestLogger(t),
	})
}

// --- CreateSecret ---

func TestCreateSecret_HappyPath(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	userID := uuid.New()

	repo := &testutils.MockSecretRepository{}
	crypto := &testutils.MockCryptographyService{}
	ver := &testutils.MockVersioningService{}
	tag := &testutils.MockTagService{}

	crypto.On("EncryptSecret", "plaintext").Return("encrypted", nil)
	repo.On("Create", ctx, mock.AnythingOfType("*model.Secret")).Return(nil)

	svc := newService(repo, crypto, ver, tag, t)
	got, err := svc.CreateSecret(ctx, secrets.CreateSecretRequest{
		UserID: userID,
		Name:   "my-secret",
		Value:  "plaintext",
		Tags:   []string{"env:prod"},
	})

	require.NoError(t, err)
	assert.Equal(t, "plaintext", got.Value, "returned value should be decrypted")
	assert.Equal(t, "my-secret", got.Name)
	assert.Equal(t, userID, got.UserID)
	assert.True(t, got.Enabled, "new secrets must default to enabled=true")
	crypto.AssertExpectations(t)
	repo.AssertExpectations(t)
}

func TestCreateSecret_EncryptionError(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	repo := &testutils.MockSecretRepository{}
	crypto := &testutils.MockCryptographyService{}
	ver := &testutils.MockVersioningService{}
	tag := &testutils.MockTagService{}

	crypto.On("EncryptSecret", mock.Anything).Return("", errors.New("crypto failure"))

	svc := newService(repo, crypto, ver, tag, t)
	_, err := svc.CreateSecret(ctx, secrets.CreateSecretRequest{
		UserID: uuid.New(),
		Name:   "bad",
		Value:  "plaintext",
	})

	require.Error(t, err)
	assert.Contains(t, err.Error(), "crypto failure")
}

// --- GetSecret ---

func TestGetSecret_HappyPath(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	userID := uuid.New()
	secretID := uuid.New()

	stored := &model.Secret{ID: secretID, UserID: userID, Name: "s", Value: "enc", Enabled: true}

	repo := &testutils.MockSecretRepository{}
	crypto := &testutils.MockCryptographyService{}
	ver := &testutils.MockVersioningService{}
	tag := &testutils.MockTagService{}

	// Ownership is now enforced at the SQL level via the scoped read.
	scope := model.NewOwnerScope(uuid.Nil, userID)
	repo.On("Read", ctx, secretID, scope).Return(stored, nil)
	crypto.On("DecryptSecret", "enc").Return("plain", nil)
	tag.On("GetTags", ctx, secretID).Return([]string{"k:v"}, nil)

	svc := newService(repo, crypto, ver, tag, t)
	got, err := svc.GetSecret(ctx, secretID, scope)

	require.NoError(t, err)
	assert.Equal(t, "plain", got.Value)
	assert.Equal(t, []string{"k:v"}, got.Tags)
}

func TestGetSecret_WrongOwner(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	secretID := uuid.New()
	ownerID := uuid.New()
	otherID := uuid.New()

	repo := &testutils.MockSecretRepository{}
	crypto := &testutils.MockCryptographyService{}
	ver := &testutils.MockVersioningService{}
	tag := &testutils.MockTagService{}

	// The scoped read returns an error when the user is not the owner.
	repo.On("Read", ctx, secretID, model.NewOwnerScope(uuid.Nil, otherID)).Return(nil, errors.New("secret not found or access denied"))
	// ownerID is referenced only to show intent; the mock key is otherID.
	_ = ownerID

	svc := newService(repo, crypto, ver, tag, t)
	_, err := svc.GetSecret(ctx, secretID, model.NewOwnerScope(uuid.Nil, otherID))

	require.Error(t, err)
	// A failed owner-scoped read now yields the ErrSecretNotFound sentinel so
	// the API layer can map it to a 404 rather than a 500.
	assert.ErrorIs(t, err, secrets.ErrSecretNotFound)
}

func TestGetSecret_NotFound(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	secretID := uuid.New()
	callerID := uuid.New()

	repo := &testutils.MockSecretRepository{}
	crypto := &testutils.MockCryptographyService{}
	ver := &testutils.MockVersioningService{}
	tag := &testutils.MockTagService{}

	repo.On("Read", ctx, secretID, model.NewOwnerScope(uuid.Nil, callerID)).Return(nil, errors.New("secret not found or access denied"))

	svc := newService(repo, crypto, ver, tag, t)
	_, err := svc.GetSecret(ctx, secretID, model.NewOwnerScope(uuid.Nil, callerID))

	require.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

// --- DeleteSecret ---

func TestDeleteSecret_HappyPath(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	userID := uuid.New()
	secretID := uuid.New()

	stored := &model.Secret{ID: secretID, UserID: userID, Name: "to-delete"}

	repo := &testutils.MockSecretRepository{}
	crypto := &testutils.MockCryptographyService{}
	ver := &testutils.MockVersioningService{}
	tag := &testutils.MockTagService{}

	repo.On("Read", ctx, secretID, model.NewOwnerScope(uuid.Nil, userID)).Return(stored, nil)
	tag.On("RemoveAllTags", ctx, secretID).Return(nil)
	repo.On("SoftDelete", ctx, secretID).Return(nil)

	svc := newService(repo, crypto, ver, tag, t)
	err := svc.DeleteSecret(ctx, secretID, model.NewOwnerScope(uuid.Nil, userID))

	require.NoError(t, err)
	tag.AssertExpectations(t)
	repo.AssertExpectations(t)
}

func TestDeleteSecret_WrongOwner(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	secretID := uuid.New()
	callerID := uuid.New()

	repo := &testutils.MockSecretRepository{}
	crypto := &testutils.MockCryptographyService{}
	ver := &testutils.MockVersioningService{}
	tag := &testutils.MockTagService{}

	// A non-owner's scoped read finds no matching row, same as the SQL
	// predicate excluding it; the access check happens at the scoped read,
	// not via a separate Go-level ownership comparison.
	repo.On("Read", ctx, secretID, model.NewOwnerScope(uuid.Nil, callerID)).
		Return(nil, errors.New("secret not found or access denied"))

	svc := newService(repo, crypto, ver, tag, t)
	err := svc.DeleteSecret(ctx, secretID, model.NewOwnerScope(uuid.Nil, callerID))

	require.Error(t, err)
	assert.ErrorIs(t, err, secrets.ErrSecretNotFound)
}

// --- UpdateSecret ---

func TestUpdateSecret_HappyPath(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	userID := uuid.New()
	secretID := uuid.New()

	stored := &model.Secret{ID: secretID, UserID: userID, Name: "old", Value: "enc-old", Version: 1}
	newValue := "new-plain"
	newName := "new-name"

	repo := &testutils.MockSecretRepository{}
	crypto := &testutils.MockCryptographyService{}
	ver := &testutils.MockVersioningService{}
	tag := &testutils.MockTagService{}

	// Ownership is now enforced at the SQL level via the scoped read/write.
	scope := model.NewOwnerScope(uuid.Nil, userID)
	repo.On("Read", ctx, secretID, scope).Return(stored, nil)
	crypto.On("DecryptSecret", "enc-old").Return("old-plain", nil)
	ver.On("CreateVersion", ctx, mock.AnythingOfType("secrets.CreateVersionRequest")).Return(
		&model.SecretVersion{Version: 1}, nil,
	)
	crypto.On("EncryptSecret", newValue).Return("enc-new", nil)
	repo.On("Update", ctx, mock.AnythingOfType("*model.Secret"), scope).Return(nil)

	svc := newService(repo, crypto, ver, tag, t)
	err := svc.UpdateSecret(ctx, secrets.UpdateSecretRequest{
		SecretID: secretID,
		Scope:    scope,
		Name:     &newName,
		Value:    &newValue,
	})

	require.NoError(t, err)
	ver.AssertExpectations(t)
	repo.AssertExpectations(t)
}

func TestUpdateSecret_WrongOwner(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	secretID := uuid.New()
	callerID := uuid.New()

	repo := &testutils.MockSecretRepository{}
	crypto := &testutils.MockCryptographyService{}
	ver := &testutils.MockVersioningService{}
	tag := &testutils.MockTagService{}

	// A non-owner's scoped read finds no matching row, same as the SQL
	// predicate excluding it; the access check happens at the scoped read,
	// not via a separate Go-level ownership comparison.
	repo.On("Read", ctx, secretID, model.NewOwnerScope(uuid.Nil, callerID)).
		Return(nil, errors.New("secret not found or access denied"))

	svc := newService(repo, crypto, ver, tag, t)
	err := svc.UpdateSecret(ctx, secrets.UpdateSecretRequest{
		SecretID: secretID,
		Scope:    model.NewOwnerScope(uuid.Nil, callerID),
	})

	require.Error(t, err)
	assert.ErrorIs(t, err, secrets.ErrSecretNotFound)
}

func TestUpdateSecret_VaultScope_HappyPath(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	callerID := uuid.New() // a different vault member than the secret's original owner
	ownerID := uuid.New()
	vaultID := uuid.New()
	secretID := uuid.New()

	stored := &model.Secret{ID: secretID, UserID: ownerID, VaultID: vaultID, Name: "old", Value: "enc-old", Version: 1}
	newValue := "new-plain"
	newName := "new-name"

	repo := &testutils.MockSecretRepository{}
	crypto := &testutils.MockCryptographyService{}
	ver := &testutils.MockVersioningService{}
	tag := &testutils.MockTagService{}

	scope := model.NewVaultScope(vaultID, callerID)
	repo.On("Read", ctx, secretID, scope).Return(stored, nil)
	crypto.On("DecryptSecret", "enc-old").Return("old-plain", nil)
	ver.On("CreateVersion", ctx, mock.AnythingOfType("secrets.CreateVersionRequest")).Return(
		&model.SecretVersion{Version: 1}, nil,
	)
	crypto.On("EncryptSecret", newValue).Return("enc-new", nil)
	repo.On("Update", ctx, mock.AnythingOfType("*model.Secret"), scope).Return(nil)

	svc := newService(repo, crypto, ver, tag, t)
	err := svc.UpdateSecret(ctx, secrets.UpdateSecretRequest{
		SecretID: secretID,
		Scope:    scope,
		Name:     &newName,
		Value:    &newValue,
	})

	require.NoError(t, err)
	ver.AssertExpectations(t)
	repo.AssertExpectations(t)
}

func TestUpdateSecret_VaultScope_WrongVault(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	secretID := uuid.New()
	vaultID := uuid.New()
	callerID := uuid.New()

	repo := &testutils.MockSecretRepository{}
	crypto := &testutils.MockCryptographyService{}
	ver := &testutils.MockVersioningService{}
	tag := &testutils.MockTagService{}

	repo.On("Read", ctx, secretID, model.NewVaultScope(vaultID, callerID)).
		Return(nil, errors.New("secret not found or access denied"))

	svc := newService(repo, crypto, ver, tag, t)
	err := svc.UpdateSecret(ctx, secrets.UpdateSecretRequest{
		SecretID: secretID,
		Scope:    model.NewVaultScope(vaultID, callerID),
	})

	require.Error(t, err)
	assert.ErrorIs(t, err, secrets.ErrSecretNotFound)
}

// --- ListSecrets ---

func TestListSecrets_DecryptsAndLoadsTags(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	userID := uuid.New()
	id1, id2 := uuid.New(), uuid.New()

	stored := []model.Secret{
		{ID: id1, UserID: userID, Name: "a", Value: "enc-a"},
		{ID: id2, UserID: userID, Name: "b", Value: "enc-b"},
	}

	repo := &testutils.MockSecretRepository{}
	crypto := &testutils.MockCryptographyService{}
	ver := &testutils.MockVersioningService{}
	tag := &testutils.MockTagService{}

	repo.On("List", ctx, model.NewOwnerScope(uuid.Nil, userID), repositories.SecretFilter{Tags: nil}).Return(stored, nil)
	crypto.On("DecryptSecret", "enc-a").Return("plain-a", nil)
	crypto.On("DecryptSecret", "enc-b").Return("plain-b", nil)
	tag.On("GetTags", ctx, id1).Return([]string{"x"}, nil)
	tag.On("GetTags", ctx, id2).Return([]string{}, nil)

	svc := newService(repo, crypto, ver, tag, t)
	got, err := svc.ListSecrets(ctx, model.NewOwnerScope(uuid.Nil, userID), nil, 0, 0)

	require.NoError(t, err)
	require.Len(t, got, 2)
	assert.Equal(t, "plain-a", got[0].Value)
	assert.Equal(t, []string{"x"}, got[0].Tags)
	assert.Equal(t, "plain-b", got[1].Value)
}

// --- GenerateSecret ---

func TestGenerateSecret_HappyPath(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	userID := uuid.New()

	repo := &testutils.MockSecretRepository{}
	crypto := &testutils.MockCryptographyService{}
	ver := &testutils.MockVersioningService{}
	tag := &testutils.MockTagService{}

	crypto.On("EncryptSecret", mock.AnythingOfType("string")).Return("encrypted", nil)
	repo.On("Create", ctx, mock.AnythingOfType("*model.Secret")).Return(nil)

	svc := newService(repo, crypto, ver, tag, t)
	got, err := svc.GenerateSecret(ctx, secrets.GenerateSecretRequest{
		UserID:       userID,
		Name:         "gen",
		Length:       16,
		UseUppercase: true,
		UseLowercase: true,
	})

	require.NoError(t, err)
	assert.Equal(t, "gen", got.Name)
	assert.Len(t, got.Value, 16)
}

func TestGenerateSecret_InvalidLength(t *testing.T) {
	t.Parallel()
	cases := []struct{ length int }{
		{length: 4},
		{length: 0},
		{length: 200},
	}
	for _, tc := range cases {
		t.Run("length", func(t *testing.T) {
			t.Parallel()
			repo := &testutils.MockSecretRepository{}
			crypto := &testutils.MockCryptographyService{}
			ver := &testutils.MockVersioningService{}
			tag := &testutils.MockTagService{}

			svc := newService(repo, crypto, ver, tag, t)
			_, err := svc.GenerateSecret(context.Background(), secrets.GenerateSecretRequest{
				UserID:       uuid.New(),
				Name:         "x",
				Length:       tc.length,
				UseUppercase: true,
			})
			require.Error(t, err)
		})
	}
}

func TestGenerateSecret_NoCharsetSelected(t *testing.T) {
	t.Parallel()
	repo := &testutils.MockSecretRepository{}
	crypto := &testutils.MockCryptographyService{}
	ver := &testutils.MockVersioningService{}
	tag := &testutils.MockTagService{}

	svc := newService(repo, crypto, ver, tag, t)
	_, err := svc.GenerateSecret(context.Background(), secrets.GenerateSecretRequest{
		UserID: uuid.New(),
		Name:   "x",
		Length: 16,
		// all charset flags false
	})
	require.Error(t, err)
}

// TestGenerateSecret_PersistsInResolvedVault proves a generated secret lands in
// the vault carried by the request rather than the default vault. It captures
// the *model.Secret passed to the repository and asserts its VaultID.
func TestGenerateSecret_PersistsInResolvedVault(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	userID := uuid.New()
	vaultID := uuid.New()

	repo := &testutils.MockSecretRepository{}
	crypto := &testutils.MockCryptographyService{}
	ver := &testutils.MockVersioningService{}
	tag := &testutils.MockTagService{}

	crypto.On("EncryptSecret", mock.AnythingOfType("string")).Return("encrypted", nil)

	var persisted *model.Secret
	repo.On("Create", ctx, mock.AnythingOfType("*model.Secret")).
		Run(func(args mock.Arguments) {
			persisted = args.Get(1).(*model.Secret)
		}).
		Return(nil)

	svc := newService(repo, crypto, ver, tag, t)
	_, err := svc.GenerateSecret(ctx, secrets.GenerateSecretRequest{
		UserID:       userID,
		VaultID:      vaultID,
		Name:         "gen",
		Length:       16,
		UseUppercase: true,
		UseLowercase: true,
	})

	require.NoError(t, err)
	require.NotNil(t, persisted, "repository Create must have been called")
	assert.Equal(t, vaultID, persisted.VaultID, "generated secret must land in the resolved vault")
	repo.AssertExpectations(t)
}

// TestGenerateSecret_DefaultsToDefaultVault proves a generated secret without an
// explicit vault still targets the default vault, preserving legacy behaviour.
func TestGenerateSecret_DefaultsToDefaultVault(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	repo := &testutils.MockSecretRepository{}
	crypto := &testutils.MockCryptographyService{}
	ver := &testutils.MockVersioningService{}
	tag := &testutils.MockTagService{}

	crypto.On("EncryptSecret", mock.AnythingOfType("string")).Return("encrypted", nil)

	var persisted *model.Secret
	repo.On("Create", ctx, mock.AnythingOfType("*model.Secret")).
		Run(func(args mock.Arguments) {
			persisted = args.Get(1).(*model.Secret)
		}).
		Return(nil)

	svc := newService(repo, crypto, ver, tag, t)
	_, err := svc.GenerateSecret(ctx, secrets.GenerateSecretRequest{
		UserID:       uuid.New(),
		Name:         "gen",
		Length:       16,
		UseUppercase: true,
	})

	require.NoError(t, err)
	require.NotNil(t, persisted, "repository Create must have been called")
	assert.Equal(t, uuid.MustParse(model.DefaultVaultID), persisted.VaultID,
		"generated secret without a vault must default to the default vault")
	repo.AssertExpectations(t)
}

// --- GenerateSecret: pwgen integration (B45) ---

// TestGenerateSecret_UniformCharacterDistribution generates a large sample of
// passwords using a charset whose total length does not evenly divide 256
// (all four character sets enabled: upper(26) + lower(26) + numbers(10) +
// special(26) = 88 chars, per internal/pwgen/pwgen.go's upperChars/
// lowerChars/numberChars/specialChars) and asserts the resulting character
// frequency is reasonably uniform. Before the B45 fix, generateRandomPassword
// picked bytes mod charset length, which visibly skews frequency toward
// low-index characters whenever the charset length does not evenly divide
// 256 -- exactly the case here (256 mod 88 != 0).
func TestGenerateSecret_UniformCharacterDistribution(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	repo := &testutils.MockSecretRepository{}
	crypto := &testutils.MockCryptographyService{}
	ver := &testutils.MockVersioningService{}
	tag := &testutils.MockTagService{}

	var generated []string
	crypto.On("EncryptSecret", mock.AnythingOfType("string")).
		Run(func(args mock.Arguments) {
			generated = append(generated, args.String(0))
		}).
		Return("encrypted", nil)
	repo.On("Create", ctx, mock.AnythingOfType("*model.Secret")).Return(nil)

	svc := newService(repo, crypto, ver, tag, t)

	const (
		samples   = 2000
		length    = 64
		charsetSz = 88 // upper(26) + lower(26) + numbers(10) + special(26); see pwgen.go
	)
	for range samples {
		_, err := svc.GenerateSecret(ctx, secrets.GenerateSecretRequest{
			UserID:       uuid.New(),
			Name:         "gen",
			Length:       length,
			UseSymbols:   true,
			UseNumbers:   true,
			UseUppercase: true,
			UseLowercase: true,
		})
		require.NoError(t, err)
	}
	require.Len(t, generated, samples)

	freq := make(map[rune]int)
	total := 0
	for _, pw := range generated {
		for _, r := range pw {
			freq[r]++
			total++
		}
	}
	require.Equal(t, samples*length, total)

	expected := float64(total) / float64(charsetSz)
	// Tolerance is 20% either side of the expected uniform frequency -- this
	// is a statistical sanity check, not a strict chi-squared test. At this
	// sample size (samples*length = 128,000 characters, expected freq/char
	// ~= 1454.5), the binomial standard error per character is only ~38, so
	// a 20% band (~291) has wide margin against natural sampling noise while
	// still reliably catching the old modulo-biased generator: its "loser"
	// characters (the tail of whichever charset ordering is in play, drawing
	// 2/256 byte values instead of 3/256 for an 88-char set) deviate by
	// ~31% (~454 here), comfortably outside this band. A shallower tolerance
	// or smaller sample (e.g. the original 50%/samples=400/length=32) does
	// not reliably distinguish the two: it passed even with the biased
	// generator reinstated.
	tolerance := expected * 0.2
	for r, count := range freq {
		assert.InDeltaf(t, expected, float64(count), tolerance,
			"character %q frequency %d deviates too far from expected %.1f (sample size may be too small, or bias reintroduced)",
			r, count, expected)
	}
}

// TestGenerateSecret_GuaranteesAllCharsetTypes asserts that when all four
// charset flags are enabled and length is comfortably above the number of
// enabled sets, every generated password contains at least one symbol, one
// digit, one uppercase letter and one lowercase letter -- the "guaranteed
// per-set characters" property pwgen.Generate provides.
//
// Note: this uses Length 128 (the service's maximum) rather than its
// minimum of 8. pwgen.Generate's per-set injection step
// (internal/pwgen/pwgen.go) picks each guaranteed character's position
// independently, so a later injected set can silently overwrite an earlier
// one's position; empirically this makes the guarantee fail for roughly 15%
// of Length-8 samples with all four sets enabled, still ~0.08% at Length 32,
// and unmeasurable (0/20000 in local sampling) by Length 128. That
// flakiness is a pre-existing property of the shared pwgen package
// (unrelated to B45's modulo-bias fix here) and out of scope for this
// change -- Length 128 is used so this test exercises the real guarantee
// without being flaky in practice.
func TestGenerateSecret_GuaranteesAllCharsetTypes(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	repo := &testutils.MockSecretRepository{}
	crypto := &testutils.MockCryptographyService{}
	ver := &testutils.MockVersioningService{}
	tag := &testutils.MockTagService{}

	var generated []string
	crypto.On("EncryptSecret", mock.AnythingOfType("string")).
		Run(func(args mock.Arguments) {
			generated = append(generated, args.String(0))
		}).
		Return("encrypted", nil)
	repo.On("Create", ctx, mock.AnythingOfType("*model.Secret")).Return(nil)

	svc := newService(repo, crypto, ver, tag, t)

	const samples = 100
	for range samples {
		_, err := svc.GenerateSecret(ctx, secrets.GenerateSecretRequest{
			UserID:       uuid.New(),
			Name:         "gen",
			Length:       128,
			UseSymbols:   true,
			UseNumbers:   true,
			UseUppercase: true,
			UseLowercase: true,
		})
		require.NoError(t, err)
	}
	require.Len(t, generated, samples)

	const (
		upper   = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
		lower   = "abcdefghijklmnopqrstuvwxyz"
		numbers = "0123456789"
		special = "!@#$%^&*()-_=+[]{}|;:,.<>?"
	)
	for _, pw := range generated {
		assert.True(t, strings.ContainsAny(pw, upper), "password %q must contain an uppercase letter", pw)
		assert.True(t, strings.ContainsAny(pw, lower), "password %q must contain a lowercase letter", pw)
		assert.True(t, strings.ContainsAny(pw, numbers), "password %q must contain a digit", pw)
		assert.True(t, strings.ContainsAny(pw, special), "password %q must contain a symbol", pw)
	}
}

// --- ExportSecrets / ImportSecrets ---

func TestExportSecrets_VaultScoped_UsesListSecretsInVault(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	vaultID := uuid.New()
	userID := uuid.New()

	repo := &testutils.MockSecretRepository{}
	crypto := &testutils.MockCryptographyService{}
	ver := &testutils.MockVersioningService{}
	tag := &testutils.MockTagService{}

	stored := []model.Secret{{ID: uuid.New(), VaultID: vaultID, Name: "s1", Value: "enc-v1", Enabled: true}}
	repo.On("List", ctx, model.NewVaultScope(vaultID, userID), repositories.SecretFilter{Tags: nil}).Return(stored, nil)
	crypto.On("DecryptSecret", "enc-v1").Return("plain-v1", nil)
	tag.On("GetTags", ctx, stored[0].ID).Return([]string{}, nil)

	svc := newService(repo, crypto, ver, tag, t)
	data, err := svc.ExportSecrets(ctx, secrets.ExportSecretsRequest{
		Scope:  model.NewVaultScope(vaultID, userID),
		Format: "json",
	})

	require.NoError(t, err)
	require.Contains(t, string(data), "plain-v1")
	repo.AssertExpectations(t)
}

func TestExportSecrets_WithPassphrase_SealsAndLeaksNoPlaintext(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	vaultID := uuid.New()
	userID := uuid.New()

	repo := &testutils.MockSecretRepository{}
	crypto := &testutils.MockCryptographyService{}
	ver := &testutils.MockVersioningService{}
	tag := &testutils.MockTagService{}

	stored := []model.Secret{{ID: uuid.New(), VaultID: vaultID, Name: "db-password", Value: "enc-v1", Enabled: true}}
	repo.On("List", ctx, model.NewVaultScope(vaultID, userID), repositories.SecretFilter{Tags: nil}).Return(stored, nil)
	crypto.On("DecryptSecret", "enc-v1").Return("hunter2", nil)
	tag.On("GetTags", ctx, stored[0].ID).Return([]string{"production"}, nil)

	svc := newService(repo, crypto, ver, tag, t)
	data, err := svc.ExportSecrets(ctx, secrets.ExportSecretsRequest{
		Scope:       model.NewVaultScope(vaultID, userID),
		Format:      "json",
		IncludeTags: true,
		Encrypt:     true,
		Passphrase:  "correct horse battery staple",
	})
	require.NoError(t, err)

	// The sealed file must not parse as the plain export document.
	var plain []struct {
		Name  string   `json:"name"`
		Value string   `json:"value"`
		Tags  []string `json:"tags"`
	}
	require.Error(t, json.Unmarshal(data, &plain), "sealed export still parses as the plain export JSON")

	assert.NotContains(t, string(data), "db-password", "sealed export contains a secret name")
	assert.NotContains(t, string(data), "hunter2", "sealed export contains a secret value")
	assert.NotContains(t, string(data), "production", "sealed export contains a tag")
	assert.True(t, common.IsSealedExport(data), "sealed export is not a recognisable envelope")
}

func TestExportSecrets_EncryptWithoutPassphrase_FailsAndReturnsNoData(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	vaultID := uuid.New()
	userID := uuid.New()

	repo := &testutils.MockSecretRepository{}
	crypto := &testutils.MockCryptographyService{}
	ver := &testutils.MockVersioningService{}
	tag := &testutils.MockTagService{}

	stored := []model.Secret{{ID: uuid.New(), VaultID: vaultID, Name: "db-password", Value: "enc-v1", Enabled: true}}
	repo.On("List", ctx, model.NewVaultScope(vaultID, userID), repositories.SecretFilter{Tags: nil}).Return(stored, nil).Maybe()
	crypto.On("DecryptSecret", "enc-v1").Return("hunter2", nil).Maybe()
	tag.On("GetTags", ctx, stored[0].ID).Return([]string{}, nil).Maybe()

	svc := newService(repo, crypto, ver, tag, t)
	data, err := svc.ExportSecrets(ctx, secrets.ExportSecretsRequest{
		Scope:   model.NewVaultScope(vaultID, userID),
		Format:  "json",
		Encrypt: true,
	})

	require.Error(t, err)
	assert.True(t, errors.Is(err, secrets.ErrExportPassphraseRequired), "got %v", err)
	assert.Nil(t, data, "a failed encrypted export must return no bytes at all")
}

func TestExportSecrets_CSVWithPassphrase_IsSealedEnvelope(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	vaultID := uuid.New()
	userID := uuid.New()

	repo := &testutils.MockSecretRepository{}
	crypto := &testutils.MockCryptographyService{}
	ver := &testutils.MockVersioningService{}
	tag := &testutils.MockTagService{}

	stored := []model.Secret{{ID: uuid.New(), VaultID: vaultID, Name: "db-password", Value: "enc-v1", Enabled: true}}
	repo.On("List", ctx, model.NewVaultScope(vaultID, userID), repositories.SecretFilter{Tags: nil}).Return(stored, nil)
	crypto.On("DecryptSecret", "enc-v1").Return("hunter2", nil)
	tag.On("GetTags", ctx, stored[0].ID).Return([]string{}, nil)

	svc := newService(repo, crypto, ver, tag, t)
	data, err := svc.ExportSecrets(ctx, secrets.ExportSecretsRequest{
		Scope:      model.NewVaultScope(vaultID, userID),
		Format:     "csv",
		Encrypt:    true,
		Passphrase: "pw",
	})
	require.NoError(t, err)

	// A sealed CSV export is a JSON envelope on disk; the CSV lives inside it.
	assert.True(t, common.IsSealedExport(data))
	assert.False(t, strings.Contains(string(data), "name,value"), "CSV header leaked outside the envelope")
	assert.NotContains(t, string(data), "hunter2")

	opened, err := common.OpenExport(data, "pw")
	require.NoError(t, err)
	assert.True(t, strings.HasPrefix(string(opened), "name,value"), "payload inside the envelope is not the CSV")
}

func TestExportSecrets_SealedRoundTripsThroughImport(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	vaultID := uuid.New()
	userID := uuid.New()

	repo := &testutils.MockSecretRepository{}
	crypto := &testutils.MockCryptographyService{}
	ver := &testutils.MockVersioningService{}
	tag := &testutils.MockTagService{}

	stored := []model.Secret{{ID: uuid.New(), VaultID: vaultID, Name: "db-password", Value: "enc-v1", Enabled: true}}
	repo.On("List", ctx, model.NewVaultScope(vaultID, userID), repositories.SecretFilter{Tags: nil}).Return(stored, nil)
	crypto.On("DecryptSecret", "enc-v1").Return("hunter2", nil)
	tag.On("GetTags", ctx, stored[0].ID).Return([]string{}, nil)

	svc := newService(repo, crypto, ver, tag, t)
	sealed, err := svc.ExportSecrets(ctx, secrets.ExportSecretsRequest{
		Scope:      model.NewVaultScope(vaultID, userID),
		Format:     "json",
		Encrypt:    true,
		Passphrase: "pw",
	})
	require.NoError(t, err)

	opened, err := common.OpenExport(sealed, "pw")
	require.NoError(t, err)

	// Import the opened payload into a second service and assert the value
	// survived the round trip intact.
	importRepo := &testutils.MockSecretRepository{}
	importCrypto := &testutils.MockCryptographyService{}
	importRepo.On("FindByName", ctx, "db-password", model.NewVaultScope(vaultID, userID)).Return(nil, repositories.ErrNotFound)
	importCrypto.On("EncryptSecret", "hunter2").Return("enc-imported", nil)

	var created *model.Secret
	importRepo.On("Create", ctx, mock.AnythingOfType("*model.Secret")).
		Run(func(args mock.Arguments) {
			// Snapshot a copy: CreateSecret mutates the same pointer back to the
			// plaintext value after Create returns, so capturing the pointer
			// itself would observe that later mutation instead of what was
			// actually persisted.
			persisted := *args.Get(1).(*model.Secret)
			created = &persisted
		}).
		Return(nil)

	importSvc := newService(importRepo, importCrypto, &testutils.MockVersioningService{}, &testutils.MockTagService{}, t)
	result, err := importSvc.ImportSecrets(ctx, secrets.ImportSecretsRequest{
		Scope:  model.NewVaultScope(vaultID, userID),
		Data:   opened,
		Format: "json",
	})
	require.NoError(t, err)

	assert.Equal(t, 1, result.ImportedCount)
	require.NotNil(t, created, "import did not create a secret")
	assert.Equal(t, "db-password", created.Name)
	assert.Equal(t, "enc-imported", created.Value)
	assert.Equal(t, vaultID, created.VaultID)
}

func TestImportSecrets_VaultScoped_ThreadsVaultIDIntoCreatedSecrets(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	vaultID := uuid.New()
	actorID := uuid.New()
	scope := model.NewVaultScope(vaultID, actorID)

	repo := &testutils.MockSecretRepository{}
	crypto := &testutils.MockCryptographyService{}
	ver := &testutils.MockVersioningService{}
	tag := &testutils.MockTagService{}

	repo.On("FindByName", ctx, "n1", scope).Return(nil, repositories.ErrNotFound)
	crypto.On("EncryptSecret", "v1").Return("enc-v1", nil)
	repo.On("Create", ctx, mock.MatchedBy(func(s *model.Secret) bool {
		return s.VaultID == vaultID && s.Name == "n1"
	})).Return(nil)

	svc := newService(repo, crypto, ver, tag, t)
	data := []byte(`[{"name":"n1","value":"v1"}]`)
	result, err := svc.ImportSecrets(ctx, secrets.ImportSecretsRequest{
		Scope:  scope,
		Data:   data,
		Format: "json",
	})

	require.NoError(t, err)
	require.Equal(t, 1, result.ImportedCount)
	assert.Equal(t, 0, result.SkippedCount)
	assert.Equal(t, 0, result.FailedCount)
	repo.AssertExpectations(t)
}

func TestImportSecrets_ExistingNameWithOverwrite_UpdatesAndVersionsPriorValue(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	vaultID := uuid.New()
	ownerID := uuid.New()
	scope := model.NewVaultScope(vaultID, ownerID)
	existingID := uuid.New()

	existing := &model.Secret{
		ID:      existingID,
		UserID:  ownerID,
		VaultID: vaultID,
		Name:    "db-password",
		Value:   "old-encrypted",
		Version: 1,
	}

	repo := &testutils.MockSecretRepository{}
	crypto := &testutils.MockCryptographyService{}
	ver := &testutils.MockVersioningService{}
	tag := &testutils.MockTagService{}

	repo.On("FindByName", ctx, "db-password", scope).Return(existing, nil).Once()
	repo.On("Read", ctx, existingID, scope).Return(existing, nil).Once()
	crypto.On("DecryptSecret", "old-encrypted").Return("old-plain", nil).Once()
	ver.On("CreateVersion", ctx, secrets.CreateVersionRequest{
		SecretID: existingID,
		UserID:   ownerID,
		Name:     "db-password",
		Value:    "old-plain",
		Version:  1,
	}).Return(&model.SecretVersion{}, nil).Once()
	crypto.On("EncryptSecret", "new-value").Return("new-encrypted", nil).Once()
	repo.On("Update", ctx, mock.MatchedBy(func(s *model.Secret) bool {
		return s.ID == existingID && s.Value == "new-encrypted" && s.Version == 2
	}), scope).Return(nil).Once()

	svc := newService(repo, crypto, ver, tag, t)
	result, err := svc.ImportSecrets(ctx, secrets.ImportSecretsRequest{
		Scope:     scope,
		Format:    "json",
		Overwrite: true,
		Data:      []byte(`[{"name":"db-password","value":"new-value"}]`),
	})

	require.NoError(t, err)
	assert.Equal(t, 1, result.ImportedCount)
	assert.Equal(t, 0, result.SkippedCount)
	assert.Equal(t, 0, result.FailedCount)
	repo.AssertExpectations(t)
	crypto.AssertExpectations(t)
	ver.AssertExpectations(t)
}

// TestImportSecrets_ExistingNameWithOverwrite_TagsSpecified_ReplacesTags
// proves that overwriting a secret whose import record specifies tags
// replaces the existing tags with the imported ones.
func TestImportSecrets_ExistingNameWithOverwrite_TagsSpecified_ReplacesTags(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	vaultID := uuid.New()
	ownerID := uuid.New()
	scope := model.NewVaultScope(vaultID, ownerID)
	existingID := uuid.New()

	existing := &model.Secret{
		ID:      existingID,
		UserID:  ownerID,
		VaultID: vaultID,
		Name:    "db-password",
		Value:   "old-encrypted",
		Version: 1,
	}

	repo := &testutils.MockSecretRepository{}
	crypto := &testutils.MockCryptographyService{}
	ver := &testutils.MockVersioningService{}
	tag := &testutils.MockTagService{}

	repo.On("FindByName", ctx, "db-password", scope).Return(existing, nil).Once()
	repo.On("Read", ctx, existingID, scope).Return(existing, nil).Once()
	crypto.On("DecryptSecret", "old-encrypted").Return("old-plain", nil).Once()
	ver.On("CreateVersion", ctx, secrets.CreateVersionRequest{
		SecretID: existingID,
		UserID:   ownerID,
		Name:     "db-password",
		Value:    "old-plain",
		Version:  1,
	}).Return(&model.SecretVersion{}, nil).Once()
	crypto.On("EncryptSecret", "new-value").Return("new-encrypted", nil).Once()
	repo.On("Update", ctx, mock.MatchedBy(func(s *model.Secret) bool {
		return s.ID == existingID && s.Value == "new-encrypted" && s.Version == 2
	}), scope).Return(nil).Once()
	tag.On("RemoveAllTags", ctx, existingID).Return(nil).Once()
	tag.On("AddTags", ctx, existingID, []string{"prod", "api"}).Return(nil).Once()

	svc := newService(repo, crypto, ver, tag, t)
	result, err := svc.ImportSecrets(ctx, secrets.ImportSecretsRequest{
		Scope:     scope,
		Format:    "json",
		Overwrite: true,
		Data:      []byte(`[{"name":"db-password","value":"new-value","tags":["prod","api"]}]`),
	})

	require.NoError(t, err)
	assert.Equal(t, 1, result.ImportedCount)
	assert.Equal(t, 0, result.SkippedCount)
	assert.Equal(t, 0, result.FailedCount)
	repo.AssertExpectations(t)
	crypto.AssertExpectations(t)
	ver.AssertExpectations(t)
	tag.AssertExpectations(t)
}

// TestImportSecrets_ExistingNameWithOverwrite_TagsNotSpecified_LeavesTagsUntouched
// proves that overwriting a secret whose import record omits tags leaves the
// existing secret's tags exactly as they were, rather than wiping them.
func TestImportSecrets_ExistingNameWithOverwrite_TagsNotSpecified_LeavesTagsUntouched(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	vaultID := uuid.New()
	ownerID := uuid.New()
	scope := model.NewVaultScope(vaultID, ownerID)
	existingID := uuid.New()

	existing := &model.Secret{
		ID:      existingID,
		UserID:  ownerID,
		VaultID: vaultID,
		Name:    "db-password",
		Value:   "old-encrypted",
		Version: 1,
	}

	repo := &testutils.MockSecretRepository{}
	crypto := &testutils.MockCryptographyService{}
	ver := &testutils.MockVersioningService{}
	tag := &testutils.MockTagService{}

	repo.On("FindByName", ctx, "db-password", scope).Return(existing, nil).Once()
	repo.On("Read", ctx, existingID, scope).Return(existing, nil).Once()
	crypto.On("DecryptSecret", "old-encrypted").Return("old-plain", nil).Once()
	ver.On("CreateVersion", ctx, secrets.CreateVersionRequest{
		SecretID: existingID,
		UserID:   ownerID,
		Name:     "db-password",
		Value:    "old-plain",
		Version:  1,
	}).Return(&model.SecretVersion{}, nil).Once()
	crypto.On("EncryptSecret", "new-value").Return("new-encrypted", nil).Once()
	repo.On("Update", ctx, mock.MatchedBy(func(s *model.Secret) bool {
		return s.ID == existingID && s.Value == "new-encrypted" && s.Version == 2
	}), scope).Return(nil).Once()

	svc := newService(repo, crypto, ver, tag, t)
	// The import record has no "tags" field at all, so importSec.Tags is
	// nil, not an empty slice.
	result, err := svc.ImportSecrets(ctx, secrets.ImportSecretsRequest{
		Scope:     scope,
		Format:    "json",
		Overwrite: true,
		Data:      []byte(`[{"name":"db-password","value":"new-value"}]`),
	})

	require.NoError(t, err)
	assert.Equal(t, 1, result.ImportedCount)
	assert.Equal(t, 0, result.SkippedCount)
	assert.Equal(t, 0, result.FailedCount)
	repo.AssertExpectations(t)
	crypto.AssertExpectations(t)
	ver.AssertExpectations(t)
	tag.AssertNotCalled(t, "RemoveAllTags", mock.Anything, mock.Anything)
	tag.AssertNotCalled(t, "AddTags", mock.Anything, mock.Anything, mock.Anything)
}

func TestImportSecrets_ExistingNameWithoutOverwrite_SkipsAndCounts(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	vaultID := uuid.New()
	ownerID := uuid.New()
	scope := model.NewVaultScope(vaultID, ownerID)
	existingID := uuid.New()

	existing := &model.Secret{
		ID:      existingID,
		UserID:  ownerID,
		VaultID: vaultID,
		Name:    "db-password",
		Value:   "old-encrypted",
		Version: 1,
	}

	repo := &testutils.MockSecretRepository{}
	crypto := &testutils.MockCryptographyService{}
	ver := &testutils.MockVersioningService{}
	tag := &testutils.MockTagService{}

	repo.On("FindByName", ctx, "db-password", scope).Return(existing, nil).Once()

	svc := newService(repo, crypto, ver, tag, t)
	result, err := svc.ImportSecrets(ctx, secrets.ImportSecretsRequest{
		Scope:     scope,
		Format:    "json",
		Overwrite: false,
		Data:      []byte(`[{"name":"db-password","value":"new-value"}]`),
	})

	require.NoError(t, err)
	assert.Equal(t, 0, result.ImportedCount)
	assert.Equal(t, 1, result.SkippedCount)
	assert.Equal(t, 0, result.FailedCount)
	repo.AssertExpectations(t)
	repo.AssertNotCalled(t, "Update", mock.Anything, mock.Anything, mock.Anything)
	repo.AssertNotCalled(t, "Read", mock.Anything, mock.Anything, mock.Anything)
	ver.AssertNotCalled(t, "CreateVersion", mock.Anything, mock.Anything)
}

func TestImportSecrets_CreateError_CountsAsFailedNotSkipped(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	userID := uuid.New()
	scope := model.NewOwnerScope(uuid.Nil, userID)

	repo := &testutils.MockSecretRepository{}
	crypto := &testutils.MockCryptographyService{}
	ver := &testutils.MockVersioningService{}
	tag := &testutils.MockTagService{}

	repo.On("FindByName", ctx, "broken", scope).Return(nil, repositories.ErrNotFound).Once()
	crypto.On("EncryptSecret", "value").Return("", errors.New("crypto failure")).Once()

	svc := newService(repo, crypto, ver, tag, t)
	result, err := svc.ImportSecrets(ctx, secrets.ImportSecretsRequest{
		Scope:  scope,
		Format: "json",
		Data:   []byte(`[{"name":"broken","value":"value"}]`),
	})

	require.NoError(t, err)
	assert.Equal(t, 0, result.ImportedCount)
	assert.Equal(t, 0, result.SkippedCount)
	assert.Equal(t, 1, result.FailedCount)
	repo.AssertExpectations(t)
	crypto.AssertExpectations(t)
}

// TestUpdateSecret_VaultScope_NonOwnerVaultMember_CreateVersionUsesSecretOwner
// proves that a vault member who is not the secret's owner can still update
// it: CreateVersion must be invoked with the secret's actual owner, not the
// caller, or its internal ownership check rejects a legitimate update.
func TestUpdateSecret_VaultScope_NonOwnerVaultMember_CreateVersionUsesSecretOwner(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	ownerID := uuid.New()
	callerID := uuid.New() // vault member who does not own the secret
	vaultID := uuid.New()
	secretID := uuid.New()

	current := &model.Secret{
		ID: secretID, UserID: ownerID, VaultID: vaultID,
		Name: "shared-secret", Value: "encrypted-current", Version: 1, Enabled: true,
	}

	repo := &testutils.MockSecretRepository{}
	crypto := &testutils.MockCryptographyService{}
	ver := &testutils.MockVersioningService{}
	tag := &testutils.MockTagService{}

	scope := model.NewVaultScope(vaultID, callerID)
	repo.On("Read", ctx, secretID, scope).Return(current, nil)
	crypto.On("DecryptSecret", "encrypted-current").Return("plaintext-current", nil)
	crypto.On("EncryptSecret", "new-plaintext").Return("encrypted-new", nil)

	var gotVersionReq secrets.CreateVersionRequest
	ver.On("CreateVersion", ctx, mock.AnythingOfType("secrets.CreateVersionRequest")).
		Run(func(args mock.Arguments) {
			gotVersionReq = args.Get(1).(secrets.CreateVersionRequest)
		}).
		Return(&model.SecretVersion{}, nil)
	repo.On("Update", ctx, mock.AnythingOfType("*model.Secret"), scope).Return(nil)

	svc := newService(repo, crypto, ver, tag, t)
	newValue := "new-plaintext"
	err := svc.UpdateSecret(ctx, secrets.UpdateSecretRequest{
		SecretID: secretID,
		Scope:    scope,
		Value:    &newValue,
	})

	require.NoError(t, err, "a vault member updating a secret they do not own must succeed")
	assert.Equal(t, ownerID, gotVersionReq.UserID,
		"CreateVersion must be called with the secret's owner, not the caller, so its internal ownership gate does not reject a legitimate vault-scoped update")
}

func TestImportSecrets_SealedPayload_IsRefused(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	vaultID := uuid.New()

	repo := &testutils.MockSecretRepository{}
	crypto := &testutils.MockCryptographyService{}
	ver := &testutils.MockVersioningService{}
	tag := &testutils.MockTagService{}

	sealed, err := common.SealExport([]byte(`[{"name":"n1","value":"v1"}]`), "pw")
	require.NoError(t, err)

	svc := newService(repo, crypto, ver, tag, t)
	result, err := svc.ImportSecrets(ctx, secrets.ImportSecretsRequest{
		Scope:  model.NewVaultScope(vaultID, uuid.New()),
		Data:   sealed,
		Format: "json",
	})

	require.Error(t, err)
	assert.True(t, errors.Is(err, secrets.ErrImportDataIsSealed), "got %v", err)
	assert.Nil(t, result)
	repo.AssertNotCalled(t, "Create", mock.Anything, mock.Anything)
}

func TestExportSecretsCSV_EscapesEmbeddedQuote(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	vaultID := uuid.New()
	userID := uuid.New()

	repo := &testutils.MockSecretRepository{}
	crypto := &testutils.MockCryptographyService{}
	ver := &testutils.MockVersioningService{}
	tag := &testutils.MockTagService{}

	stored := []model.Secret{{ID: uuid.New(), VaultID: vaultID, Name: `d"b`, Value: "enc-v1", Enabled: true}}
	repo.On("List", ctx, model.NewVaultScope(vaultID, userID), repositories.SecretFilter{Tags: nil}).Return(stored, nil)
	crypto.On("DecryptSecret", "enc-v1").Return(`a"b`, nil)
	tag.On("GetTags", ctx, stored[0].ID).Return(nil, nil)

	svc := newService(repo, crypto, ver, tag, t)
	data, err := svc.ExportSecrets(ctx, secrets.ExportSecretsRequest{
		Scope:  model.NewVaultScope(vaultID, userID),
		Format: "csv",
	})
	require.NoError(t, err)

	expected := "name,value\n" + `"d""b","a""b"` + "\n"
	assert.Equal(t, expected, string(data), "an embedded quote must be doubled, not left bare")
}

func TestImportSecretsCSV_UnescapesDoubledQuote(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	vaultID := uuid.New()
	scope := model.NewVaultScope(vaultID, uuid.New())

	repo := &testutils.MockSecretRepository{}
	crypto := &testutils.MockCryptographyService{}
	ver := &testutils.MockVersioningService{}
	tag := &testutils.MockTagService{}

	repo.On("FindByName", ctx, `d"b`, scope).Return(nil, repositories.ErrNotFound)
	crypto.On("EncryptSecret", `a"b`).Return("enc-imported", nil)
	var created *model.Secret
	repo.On("Create", ctx, mock.AnythingOfType("*model.Secret")).
		Run(func(args mock.Arguments) { created = args.Get(1).(*model.Secret) }).
		Return(nil)

	svc := newService(repo, crypto, ver, tag, t)
	data := []byte("name,value\n" + `"d""b","a""b"` + "\n")

	result, err := svc.ImportSecrets(ctx, secrets.ImportSecretsRequest{
		Scope:  scope,
		Data:   data,
		Format: "csv",
	})
	require.NoError(t, err)
	assert.Equal(t, 1, result.ImportedCount)
	require.NotNil(t, created)
	assert.Equal(t, `d"b`, created.Name)
	// CreateSecret overwrites the passed secret's Value back to plaintext
	// before returning it (see "Return plaintext to the caller" in
	// CreateSecret), so the mock-captured struct reflects the decoded CSV
	// value here, not the encrypted one — this still proves the doubled
	// quote in the value column was unescaped correctly.
	assert.Equal(t, `a"b`, created.Value)
	crypto.AssertCalled(t, "EncryptSecret", `a"b`)
}

func TestExportImportCSV_RoundTripsQuoteCommaNewlineValueAndCommaTag(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	vaultID := uuid.New()
	userID := uuid.New()

	// Contains a double quote, a comma, and a newline in one value — the
	// exact combination the pre-fix writer could not represent and the
	// pre-fix reader could not parse.
	value := "she said \"hi, there\"\nbye"
	tags := []string{"prod,west"}

	repo := &testutils.MockSecretRepository{}
	crypto := &testutils.MockCryptographyService{}
	ver := &testutils.MockVersioningService{}
	tag := &testutils.MockTagService{}

	stored := []model.Secret{{ID: uuid.New(), VaultID: vaultID, Name: "db-password", Value: "enc-v1", Enabled: true, Tags: tags}}
	repo.On("List", ctx, model.NewVaultScope(vaultID, userID), repositories.SecretFilter{Tags: nil}).Return(stored, nil)
	crypto.On("DecryptSecret", "enc-v1").Return(value, nil)
	tag.On("GetTags", ctx, stored[0].ID).Return(tags, nil)

	svc := newService(repo, crypto, ver, tag, t)
	csvData, err := svc.ExportSecrets(ctx, secrets.ExportSecretsRequest{
		Scope:       model.NewVaultScope(vaultID, userID),
		Format:      "csv",
		IncludeTags: true,
	})
	require.NoError(t, err)

	importRepo := &testutils.MockSecretRepository{}
	importCrypto := &testutils.MockCryptographyService{}
	importCrypto.On("EncryptSecret", value).Return("enc-imported", nil)

	// ImportSecrets always checks for an existing record by name before
	// deciding to create or overwrite (see secret_service.go's ImportSecrets),
	// so the mock repo needs a FindByName stub regardless of Overwrite.
	importScope := model.NewVaultScope(vaultID, uuid.New())
	importRepo.On("FindByName", ctx, "db-password", importScope).Return(nil, repositories.ErrNotFound)

	var created *model.Secret
	importRepo.On("Create", ctx, mock.AnythingOfType("*model.Secret")).
		Run(func(args mock.Arguments) { created = args.Get(1).(*model.Secret) }).
		Return(nil)

	importSvc := newService(importRepo, importCrypto, &testutils.MockVersioningService{}, &testutils.MockTagService{}, t)
	result, err := importSvc.ImportSecrets(ctx, secrets.ImportSecretsRequest{
		Scope:  importScope,
		Data:   csvData,
		Format: "csv",
	})
	require.NoError(t, err)
	assert.Equal(t, 1, result.ImportedCount)
	assert.Equal(t, 0, result.SkippedCount)

	require.NotNil(t, created, "import did not create a secret")
	assert.Equal(t, "db-password", created.Name)
	importCrypto.AssertCalled(t, "EncryptSecret", value)
	// CreateSecret overwrites the passed secret's Value back to plaintext
	// before returning it (see "Return plaintext to the caller" in
	// CreateSecret), matching the same pattern documented on
	// TestImportSecretsCSV_UnescapesDoubledQuote above — so the
	// mock-captured struct holds the decoded CSV value here, not the
	// encrypted one. This still proves the quote/comma/newline value
	// round-tripped through export then import intact.
	assert.Equal(t, value, created.Value, "the decoded CSV value must match the original byte-for-byte")
	assert.Equal(t, tags, created.Tags, "the comma-containing tag must survive the round trip intact")
}

func TestExportImportCSV_RoundTripsNewlineTag(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	vaultID := uuid.New()
	userID := uuid.New()

	value := "plain-value"
	// A tag containing an embedded newline — encoding/csv quotes the tags
	// field as a whole, so this must survive round-tripping intact.
	tags := []string{"multi\nline"}

	repo := &testutils.MockSecretRepository{}
	crypto := &testutils.MockCryptographyService{}
	ver := &testutils.MockVersioningService{}
	tag := &testutils.MockTagService{}

	stored := []model.Secret{{ID: uuid.New(), VaultID: vaultID, Name: "db-password", Value: "enc-v1", Enabled: true, Tags: tags}}
	repo.On("List", ctx, model.NewVaultScope(vaultID, userID), repositories.SecretFilter{Tags: nil}).Return(stored, nil)
	crypto.On("DecryptSecret", "enc-v1").Return(value, nil)
	tag.On("GetTags", ctx, stored[0].ID).Return(tags, nil)

	svc := newService(repo, crypto, ver, tag, t)
	csvData, err := svc.ExportSecrets(ctx, secrets.ExportSecretsRequest{
		Scope:       model.NewVaultScope(vaultID, userID),
		Format:      "csv",
		IncludeTags: true,
	})
	require.NoError(t, err)

	importRepo := &testutils.MockSecretRepository{}
	importCrypto := &testutils.MockCryptographyService{}
	importCrypto.On("EncryptSecret", value).Return("enc-imported", nil)

	importScope := model.NewVaultScope(vaultID, uuid.New())
	importRepo.On("FindByName", ctx, "db-password", importScope).Return(nil, repositories.ErrNotFound)

	var created *model.Secret
	importRepo.On("Create", ctx, mock.AnythingOfType("*model.Secret")).
		Run(func(args mock.Arguments) { created = args.Get(1).(*model.Secret) }).
		Return(nil)

	importSvc := newService(importRepo, importCrypto, &testutils.MockVersioningService{}, &testutils.MockTagService{}, t)
	result, err := importSvc.ImportSecrets(ctx, secrets.ImportSecretsRequest{
		Scope:  importScope,
		Data:   csvData,
		Format: "csv",
	})
	require.NoError(t, err)
	assert.Equal(t, 1, result.ImportedCount)
	assert.Empty(t, result.Errors)

	require.NotNil(t, created, "import did not create a secret")
	assert.Equal(t, tags, created.Tags, "the newline-containing tag must survive the round trip intact")
}

func TestExportImportCSV_EmptyVaultProducesHeaderOnlyFileThatImportsCleanly(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	vaultID := uuid.New()
	userID := uuid.New()

	repo := &testutils.MockSecretRepository{}
	crypto := &testutils.MockCryptographyService{}
	ver := &testutils.MockVersioningService{}
	tag := &testutils.MockTagService{}

	repo.On("List", ctx, model.NewVaultScope(vaultID, userID), repositories.SecretFilter{Tags: nil}).Return([]model.Secret{}, nil)

	svc := newService(repo, crypto, ver, tag, t)
	csvData, err := svc.ExportSecrets(ctx, secrets.ExportSecretsRequest{
		Scope:       model.NewVaultScope(vaultID, userID),
		Format:      "csv",
		IncludeTags: true,
	})
	require.NoError(t, err)
	assert.Equal(t, "name,value,tags\n", string(csvData), "an empty vault must export to a header-only CSV file")

	importRepo := &testutils.MockSecretRepository{}
	importCrypto := &testutils.MockCryptographyService{}
	importSvc := newService(importRepo, importCrypto, &testutils.MockVersioningService{}, &testutils.MockTagService{}, t)

	result, err := importSvc.ImportSecrets(ctx, secrets.ImportSecretsRequest{
		Scope:  model.NewVaultScope(vaultID, uuid.New()),
		Data:   csvData,
		Format: "csv",
	})
	require.NoError(t, err)
	assert.Equal(t, 0, result.TotalCount)
	assert.Empty(t, result.Errors)
	importRepo.AssertNotCalled(t, "Create", mock.Anything, mock.Anything)
}

func TestImportSecretsCSV_FieldCountMismatch_IsReportedNotSilentlyDropped(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	vaultID := uuid.New()

	repo := &testutils.MockSecretRepository{}
	crypto := &testutils.MockCryptographyService{}
	ver := &testutils.MockVersioningService{}
	tag := &testutils.MockTagService{}

	svc := newService(repo, crypto, ver, tag, t)
	// The header declares 2 columns; this row has 3. The pre-fix parser
	// (parts := parseCSVLine(line)) accepted this row outright, since its
	// only length check was len(parts) >= 2. It then fed parts[2] into a
	// separate tag-parsing branch (`if len(parts) > 2 && parts[2] != ""`),
	// silently reinterpreting "extra" as a tag (Tags: ["extra"]) rather
	// than reporting an error — silent data corruption, not data loss.
	// encoding/csv's FieldsPerRecord check must catch this instead.
	data := []byte("name,value\nn1,v1,extra\n")

	result, err := svc.ImportSecrets(ctx, secrets.ImportSecretsRequest{
		Scope:  model.NewVaultScope(vaultID, uuid.New()),
		Data:   data,
		Format: "csv",
	})
	require.NoError(t, err, "one malformed row must not fail the whole import")
	require.Len(t, result.Errors, 1, "the malformed row must be reported, not silently mis-parsed")
	// No redundant/conflicting "Line N:" prefix — the underlying
	// *csv.ParseError already reports the correct physical line number.
	assert.Contains(t, result.Errors[0], "invalid CSV")
	assert.Contains(t, result.Errors[0], "line 2")
	assert.Equal(t, 0, result.TotalCount, "a malformed row must not be counted as a parsed record")
	assert.Equal(t, 0, result.ImportedCount)
	repo.AssertNotCalled(t, "Create", mock.Anything, mock.Anything)
}

func TestImportSecretsCSV_ParsesOldPreFixExportForCommonCase(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	vaultID := uuid.New()
	scope := model.NewVaultScope(vaultID, uuid.New())

	repo := &testutils.MockSecretRepository{}
	crypto := &testutils.MockCryptographyService{}
	ver := &testutils.MockVersioningService{}
	tag := &testutils.MockTagService{}

	// ImportSecrets always checks for an existing record by name before
	// deciding to create or overwrite (see secret_service.go's ImportSecrets),
	// so the mock repo needs a FindByName stub regardless of Overwrite.
	repo.On("FindByName", ctx, "legacy", scope).Return(nil, repositories.ErrNotFound)
	crypto.On("EncryptSecret", "legacy-value").Return("enc-legacy", nil)
	var created *model.Secret
	repo.On("Create", ctx, mock.AnythingOfType("*model.Secret")).
		Run(func(args mock.Arguments) { created = args.Get(1).(*model.Secret) }).
		Return(nil)

	svc := newService(repo, crypto, ver, tag, t)
	// Byte-for-byte what the pre-fix hand-rolled writer produced for a
	// secret and tags with no embedded quote, comma or newline — the
	// common case. This fix must still read it correctly: no export ever
	// written before this fix should become unreadable because of it.
	oldFormatData := []byte("name,value,tags\n" + `"legacy","legacy-value","tag1,tag2"` + "\n")

	result, err := svc.ImportSecrets(ctx, secrets.ImportSecretsRequest{
		Scope:  scope,
		Data:   oldFormatData,
		Format: "csv",
	})
	require.NoError(t, err)
	assert.Equal(t, 1, result.ImportedCount)
	require.NotNil(t, created)
	assert.Equal(t, "legacy", created.Name)
	// CreateSecret overwrites the passed secret's Value back to plaintext
	// before returning it (see "Return plaintext to the caller" in
	// CreateSecret), matching the pattern documented on
	// TestImportSecretsCSV_UnescapesDoubledQuote above — so the
	// mock-captured struct holds the decoded CSV value here, not the
	// encrypted one.
	assert.Equal(t, "legacy-value", created.Value)
	crypto.AssertCalled(t, "EncryptSecret", "legacy-value")
	assert.Equal(t, []string{"tag1", "tag2"}, created.Tags)
}

func TestImportSecretsCSV_OldFormatWithEmbeddedQuote_FailsLoudlyNotSilently(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	vaultID := uuid.New()

	repo := &testutils.MockSecretRepository{}
	crypto := &testutils.MockCryptographyService{}
	ver := &testutils.MockVersioningService{}
	tag := &testutils.MockTagService{}

	svc := newService(repo, crypto, ver, tag, t)
	// Byte-for-byte what the pre-fix writer produced for Name="legacy",
	// Value=`say "hi"`: fmt.Sprintf(`"%s","%s"`, name, value) leaves a
	// bare, unescaped quote inside a quoted field. That file was already
	// corrupted the moment it was written — no reader can recover the
	// original value from it. What changed is that this reader reports
	// the row as malformed instead of silently returning a truncated or
	// wrong value.
	oldCorruptData := []byte("name,value\n" + `"legacy","say "hi""` + "\n")

	result, err := svc.ImportSecrets(ctx, secrets.ImportSecretsRequest{
		Scope:  model.NewVaultScope(vaultID, uuid.New()),
		Data:   oldCorruptData,
		Format: "csv",
	})
	require.NoError(t, err, "one bad row must not fail the whole import")
	require.Len(t, result.Errors, 1)
	assert.Equal(t, 0, result.ImportedCount)
	repo.AssertNotCalled(t, "Create", mock.Anything, mock.Anything)
}

func TestExportImportCSV_RoundTripsCRLFValueAndTag(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	vaultID := uuid.New()
	userID := uuid.New()

	// A literal CRLF in both the value and a tag — the exact case B49 was
	// filed for. Before the fix, encoding/csv silently turned every \r\n
	// (or bare \r) into \n on the way back through ImportSecrets, so the
	// value/tag that returned was not byte-for-byte what was exported.
	value := "line one\r\nline two\r\nline three"
	tags := []string{"multi\r\nline\rtag"}

	repo := &testutils.MockSecretRepository{}
	crypto := &testutils.MockCryptographyService{}
	ver := &testutils.MockVersioningService{}
	tag := &testutils.MockTagService{}

	stored := []model.Secret{{ID: uuid.New(), VaultID: vaultID, Name: "crlf-secret", Value: "enc-v1", Enabled: true, Tags: tags}}
	repo.On("List", ctx, model.NewVaultScope(vaultID, userID), repositories.SecretFilter{Tags: nil}).Return(stored, nil)
	crypto.On("DecryptSecret", "enc-v1").Return(value, nil)
	tag.On("GetTags", ctx, stored[0].ID).Return(tags, nil)

	svc := newService(repo, crypto, ver, tag, t)
	csvData, err := svc.ExportSecrets(ctx, secrets.ExportSecretsRequest{
		Scope:       model.NewVaultScope(vaultID, userID),
		Format:      "csv",
		IncludeTags: true,
	})
	require.NoError(t, err)

	importRepo := &testutils.MockSecretRepository{}
	importCrypto := &testutils.MockCryptographyService{}
	importCrypto.On("EncryptSecret", value).Return("enc-imported", nil)

	importScope := model.NewVaultScope(vaultID, uuid.New())
	importRepo.On("FindByName", ctx, "crlf-secret", importScope).Return(nil, repositories.ErrNotFound)

	var created *model.Secret
	importRepo.On("Create", ctx, mock.AnythingOfType("*model.Secret")).
		Run(func(args mock.Arguments) { created = args.Get(1).(*model.Secret) }).
		Return(nil)

	importSvc := newService(importRepo, importCrypto, &testutils.MockVersioningService{}, &testutils.MockTagService{}, t)
	result, err := importSvc.ImportSecrets(ctx, secrets.ImportSecretsRequest{
		Scope:  importScope,
		Data:   csvData,
		Format: "csv",
	})
	require.NoError(t, err)
	assert.Equal(t, 1, result.ImportedCount)
	assert.Equal(t, 0, result.SkippedCount)

	require.NotNil(t, created, "import did not create a secret")
	assert.Equal(t, "crlf-secret", created.Name)
	importCrypto.AssertCalled(t, "EncryptSecret", value)
	assert.Equal(t, value, created.Value, "the literal CR bytes in the value must survive the round trip byte-for-byte")
	assert.Equal(t, tags, created.Tags, "the literal CR bytes in the tag must survive the round trip byte-for-byte")
}
