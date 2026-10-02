// Package vaults provides the vault lifecycle service.
package vaults

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"

	"rocketvault/internal/db"
	"rocketvault/internal/logging"
	"rocketvault/internal/repositories"
	"rocketvault/model"
)

// defaultRetentionDays is the soft-delete retention applied to new vaults.
const defaultRetentionDays = 90

// ErrVaultNotFound is returned when a vault cannot be found by name.
var ErrVaultNotFound = errors.New("vault not found")

// ErrDefaultVaultProtected is returned when an operation refuses to act on
// the default vault (e.g. delete, purge).
var ErrDefaultVaultProtected = errors.New("default vault is protected from this operation")

// ErrVaultPurgeProtected is returned when PurgeVault refuses to act because
// the vault has purge protection enabled.
var ErrVaultPurgeProtected = errors.New("vault is protected from purge")

// ErrVaultContentsPurgeProtected is returned when PurgeVault refuses to act
// because a secret, key, or certificate inside the vault has its own
// purge_protection flag enabled. Without this check, purging the vault would
// bypass that item's protection entirely -- the same guarantee the item's own
// manual purge path already enforces (see internal/repositories's
// Err{Secret,Key,Cert}PurgeProtected).
var ErrVaultContentsPurgeProtected = errors.New("vault contains items protected from purge")

// CascadeRepository soft-deletes, recovers, or purges all resources belonging to a vault.
type CascadeRepository interface {
	SoftDeleteVaultContents(ctx context.Context, vaultID uuid.UUID, deletedAt time.Time) error
	RecoverVaultContents(ctx context.Context, vaultID uuid.UUID, deletedAt time.Time) error
	// SoftDeleteVaultContentsTx is SoftDeleteVaultContents scoped to an explicit executor.
	SoftDeleteVaultContentsTx(ctx context.Context, ex db.DBTX, vaultID uuid.UUID, deletedAt time.Time) error
	// RecoverVaultContentsTx is RecoverVaultContents scoped to an explicit executor.
	RecoverVaultContentsTx(ctx context.Context, ex db.DBTX, vaultID uuid.UUID, deletedAt time.Time) error
	// PurgeVaultContents permanently deletes every secret/key/certificate row
	// belonging to a vault, active or already soft-deleted. Secrets, keys,
	// and certificates carry no foreign key on vault_id, so without this
	// call PurgeVault would strand their rows permanently, unreachable but
	// never removed.
	PurgeVaultContents(ctx context.Context, vaultID uuid.UUID) error
	// HasProtectedContent reports whether any secret, key, or certificate in
	// the vault (active or soft-deleted) has purge_protection enabled.
	// PurgeVault refuses to proceed when this is true.
	HasProtectedContent(ctx context.Context, vaultID uuid.UUID) (bool, error)
}

// PolicyCleaner removes access policies scoped to a vault (used on purge).
type PolicyCleaner interface {
	DeleteByVault(ctx context.Context, vaultID uuid.UUID) error
}

// GrantLocker locks a principal's provisioning grant inside a transaction and
// returns its quota. Satisfied by the concrete
// repositories.vaultProvisioningGrantRepository.
type GrantLocker interface {
	LockAndReadQuotaTx(ctx context.Context, ex db.DBTX, principalID uuid.UUID) (int, error)
}

// CreatorGranter writes the creator's rights over a newly provisioned vault,
// inside the caller's transaction. Satisfied by an adapter over the concrete
// access-policy and role-assignment repositories.
type CreatorGranter interface {
	CreatePolicyTx(ctx context.Context, ex db.DBTX, p *model.AccessPolicy) error
	CreateRoleTx(ctx context.Context, ex db.DBTX, ra *model.RoleAssignment) error
}

// RoleAssignmentCleaner removes role assignments scoped to a vault (used on
// purge). Separate from PolicyCleaner because the two are different tables
// with different repositories, and either may be absent in a unit test.
type RoleAssignmentCleaner interface {
	DeleteByVault(ctx context.Context, vaultID uuid.UUID) error
}

// PolicyVaultLister lists the vaults a principal holds scoped management over.
type PolicyVaultLister interface {
	ListVaultIDsForPrincipal(ctx context.Context, principalID uuid.UUID) ([]uuid.UUID, error)
}

// WebhookCleaner removes a vault's webhook config (used on purge). Satisfied
// by repositories.VaultWebhookRepositoryInterface.
//
// This is required, not belt-and-braces: vault_webhook_configs declares a
// FOREIGN KEY ... ON DELETE CASCADE, but SQLite's foreign_keys PRAGMA is off
// in this project, so that clause never fires there. Without this hook a
// purged vault strands a row holding an encrypted signing secret -- the same
// reason PurgeVaultContents and DeleteByVault below exist.
type WebhookCleaner interface {
	DeleteByVaultID(ctx context.Context, vaultID uuid.UUID) error
}

// SecretCacheFlusher empties the secret cache. The delete/recover cascade
// stamps deleted_at on every secret in a vault with one UPDATE, so the ids it
// touched are never enumerated and per-id eviction is not possible; a flush is
// the only correct primitive. Satisfied by *cache.SecretCache.
type SecretCacheFlusher interface {
	Flush(ctx context.Context) error
}

// VaultCacheInterface caches vault records by name. Satisfied by
// *vaultcache.Cache. Declared here (not imported from internal/vaultcache)
// to keep this package import-cycle-free, matching the existing
// SecretCacheFlusher pattern in this same file.
type VaultCacheInterface interface {
	Get(name string) (*model.Vault, bool)
	Set(name string, v *model.Vault)
	Invalidate(name string)
}

// TxBeginner begins a transaction usable by the Tx-scoped repository/cascade
// methods. Satisfied by *db.Conn. Injected via SetTxBeginner so unit tests
// that construct a vaultService without a real database (every existing test
// in this package) keep exercising the pre-existing non-transactional path.
type TxBeginner interface {
	BeginTx(ctx context.Context, opts *sql.TxOptions) (*db.Tx, error)
}

// txCapableVaultRepo is implemented by VaultRepositoryInterface's concrete
// type when it also supports the Tx-scoped delete/recover cascade. The
// Tx-scoped methods live only on the concrete VaultRepository struct (Task
// 6's Step 0), not on the exported VaultRepositoryInterface, so adding them
// doesn't ripple to every test double implementing that interface. A type
// assertion recovers the capability from s.repo's dynamic type -- always
// present for the real *repositories.VaultRepository, never exercised by
// test fakes (which never call SetTxBeginner, so this branch never runs
// for them).
type txCapableVaultRepo interface {
	ReadByIDTx(ctx context.Context, ex db.DBTX, id uuid.UUID) (*model.Vault, error)
	SoftDeleteTx(ctx context.Context, ex db.DBTX, id uuid.UUID) error
	RecoverTx(ctx context.Context, ex db.DBTX, id uuid.UUID) error
}

// txCapableCreateRepo is the provisioned-create half of the concrete
// VaultRepository's Tx surface. Kept off VaultRepositoryInterface for the
// same reason as txCapableVaultRepo: adding it there would ripple to every
// test double implementing that interface.
type txCapableCreateRepo interface {
	CreateTx(ctx context.Context, ex db.DBTX, v *model.Vault) error
	CountByCreatedBy(ctx context.Context, ex db.DBTX, principalID uuid.UUID) (int, error)
}

// VaultService orchestrates the vault lifecycle.
type VaultService interface {
	CreateVault(ctx context.Context, req model.CreateVaultRequest, createdBy uuid.UUID) (*model.Vault, error)
	// CreateVaultProvisioned creates a vault, enforcing the caller's
	// provisioning quota when quotaBounded is true and granting the caller
	// full management rights over the vault it creates when grantCreatorRights
	// is true. Both are passed in by the caller, derived from
	// authz.CreateRight -- this method does not re-derive the authorization
	// decision. quotaBounded = right == CreateRightProvisioningGrant;
	// grantCreatorRights = right != CreateRightAdmin.
	CreateVaultProvisioned(ctx context.Context, req model.CreateVaultRequest, createdBy uuid.UUID, quotaBounded, grantCreatorRights bool) (*model.Vault, error)
	GetVault(ctx context.Context, name string) (*model.Vault, error)
	ListVaults(ctx context.Context, includeDeleted bool) ([]model.Vault, error)
	// ListVaultsScoped returns every vault when all is true (the admin and
	// global-policy path, identical to ListVaults), and otherwise only vaults
	// where principalID holds a vault-scoped vaults:manage allow.
	ListVaultsScoped(ctx context.Context, principalID uuid.UUID, includeDeleted, all bool) ([]model.Vault, error)
	UpdateVault(ctx context.Context, name string, req model.UpdateVaultRequest, updatedBy uuid.UUID) (*model.Vault, error)
	DeleteVault(ctx context.Context, name string) error
	RecoverVault(ctx context.Context, name string) error
	PurgeVault(ctx context.Context, name string) error
	SetPolicyCleaner(p PolicyCleaner)
	SetRoleAssignmentCleaner(c RoleAssignmentCleaner)
	SetWebhookCleaner(c WebhookCleaner)
	SetTxBeginner(tb TxBeginner)
	SetSecretCacheFlusher(f SecretCacheFlusher)
	SetVaultCache(c VaultCacheInterface)
	// SetGlobalPurgeProtection mirrors soft_delete.purge_protection. When set
	// true, PurgeVault refuses every purge instance-wide, regardless of this
	// vault's or its contents' own purge_protection flag.
	SetGlobalPurgeProtection(protected bool)
	// SetGrantLocker attaches the provisioning-grant locker used by the
	// quota-bounded create path.
	SetGrantLocker(l GrantLocker)
	// SetCreatorGranter attaches the writer that grants the creator full
	// management rights over a vault it provisions, inside the same
	// transaction as the vault insert.
	SetCreatorGranter(g CreatorGranter)
	// SetPolicyVaultLister attaches the policy-vault lister used by
	// ListVaultsScoped's non-admin path.
	SetPolicyVaultLister(l PolicyVaultLister)
}

type vaultService struct {
	repo                  repositories.VaultRepositoryInterface
	cascade               CascadeRepository
	policies              PolicyCleaner
	roleAssignments       RoleAssignmentCleaner
	webhooks              WebhookCleaner
	txBeginner            TxBeginner
	secretCache           SecretCacheFlusher
	vaultCache            VaultCacheInterface
	log                   *logging.Logger
	globalPurgeProtection bool
	grantLocker           GrantLocker
	creatorGranter        CreatorGranter
	policyVaults          PolicyVaultLister
}

// NewVaultService constructs a VaultService backed by the given repository and cascade handler.
func NewVaultService(repo repositories.VaultRepositoryInterface, cascade CascadeRepository, log *logging.Logger) VaultService {
	return &vaultService{repo: repo, cascade: cascade, log: log}
}

// SetPolicyCleaner attaches an optional cleaner that removes vault-scoped access policies on purge.
func (s *vaultService) SetPolicyCleaner(p PolicyCleaner) { s.policies = p }

// SetRoleAssignmentCleaner attaches an optional cleaner that removes
// vault-scoped role assignments on purge.
func (s *vaultService) SetRoleAssignmentCleaner(c RoleAssignmentCleaner) { s.roleAssignments = c }

// SetWebhookCleaner attaches an optional cleaner that removes a vault's
// webhook config on purge.
func (s *vaultService) SetWebhookCleaner(c WebhookCleaner) { s.webhooks = c }

// SetGlobalPurgeProtection sets the instance-wide purge safety switch. See
// vaultService.globalPurgeProtection.
func (s *vaultService) SetGlobalPurgeProtection(protected bool) { s.globalPurgeProtection = protected }

// SetGrantLocker attaches the provisioning-grant locker used by the
// quota-bounded create path.
func (s *vaultService) SetGrantLocker(l GrantLocker) { s.grantLocker = l }

// SetCreatorGranter attaches the writer that grants the creator full
// management rights over a vault it provisions, inside the same transaction
// as the vault insert.
func (s *vaultService) SetCreatorGranter(g CreatorGranter) { s.creatorGranter = g }

// SetPolicyVaultLister attaches the policy-vault lister used by
// ListVaultsScoped's non-admin path.
func (s *vaultService) SetPolicyVaultLister(l PolicyVaultLister) { s.policyVaults = l }

// SetTxBeginner attaches an optional transaction beginner. When set,
// DeleteVault/RecoverVault run their cascade atomically inside one
// transaction; when unset, they run the pre-existing non-transactional
// sequence.
func (s *vaultService) SetTxBeginner(tb TxBeginner) { s.txBeginner = tb }

// SetSecretCacheFlusher attaches an optional secret-cache flusher. When set,
// DeleteVault and RecoverVault flush the cache after the cascade commits, so a
// secret soft-deleted (or restored) by the cascade is not still served from a
// cache entry primed before the change. Unset means caching is disabled.
func (s *vaultService) SetSecretCacheFlusher(f SecretCacheFlusher) { s.secretCache = f }

// SetVaultCache attaches an optional vault-by-name cache. When set,
// getByName consults it before the repository and populates it on a miss;
// Update/Delete/Recover/Purge invalidate the entry after a successful write.
// Unset means vault caching is disabled.
func (s *vaultService) SetVaultCache(c VaultCacheInterface) { s.vaultCache = c }

// flushSecretCache empties the secret cache after a cascade. It runs only on
// the success path (post-commit), so a rolled-back cascade never evicts, and a
// flush failure is logged rather than failing the completed operation.
func (s *vaultService) flushSecretCache(ctx context.Context, vaultID uuid.UUID, operation string) {
	if s.secretCache == nil {
		return
	}
	if err := s.secretCache.Flush(ctx); err != nil && s.log != nil {
		s.log.WithError(err).WithField("vault_id", vaultID).
			Warnf("Failed to flush secret cache after %s", operation)
	}
}

// withTx runs fn inside a transaction begun via txBeginner, committing on
// success and rolling back on error. Mirrors db.WithTx's commit/rollback
// semantics but operates on the dialect-aware db.Tx the repository layer
// uses, rather than a raw *sql.Tx.
func (s *vaultService) withTx(ctx context.Context, fn func(tx *db.Tx) error) error {
	tx, err := s.txBeginner.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin transaction: %w", err)
	}
	if err := fn(tx); err != nil {
		if rbErr := tx.Rollback(); rbErr != nil {
			return fmt.Errorf("rollback failed: %w (original: %v)", rbErr, err)
		}
		return err
	}
	return tx.Commit()
}

// buildVault applies request defaults and overrides to a new, unpersisted
// vault. Shared by CreateVault and CreateVaultProvisioned so the two paths'
// defaults cannot drift apart -- callers still validate req before calling
// this, buildVault itself doesn't.
func (s *vaultService) buildVault(req model.CreateVaultRequest, createdBy uuid.UUID) *model.Vault {
	v := &model.Vault{
		ID:            uuid.New(),
		Name:          req.Name,
		Enabled:       true,
		RetentionDays: defaultRetentionDays,
		Tags:          req.Tags,
		CreatedBy:     createdBy,
		CreatedAt:     time.Now(),
	}
	if req.Enabled != nil {
		v.Enabled = *req.Enabled
	}
	if req.PurgeProtection != nil {
		v.PurgeProtection = *req.PurgeProtection
	}
	if req.RetentionDays != nil {
		v.RetentionDays = *req.RetentionDays
	}
	return v
}

// CreateVault validates the request, applies defaults and overrides, and persists a new vault.
func (s *vaultService) CreateVault(ctx context.Context, req model.CreateVaultRequest, createdBy uuid.UUID) (*model.Vault, error) {
	if err := model.ValidateNewVaultName(req.Name); err != nil {
		return nil, err
	}
	if err := model.ValidateVaultTags(req.Tags); err != nil {
		return nil, err
	}

	v := s.buildVault(req, createdBy)

	if err := s.repo.Create(ctx, v); err != nil {
		return nil, fmt.Errorf("create vault: %w", err)
	}
	if s.log != nil {
		s.log.LogAuditInfo(createdBy.String(), "create_vault", "success", fmt.Sprintf("Vault created: %s", v.Name))
	}
	return v, nil
}

// ErrVaultQuotaExceeded means the principal has reached the vault count its
// provisioning grant allows. Soft-deleted vaults still count -- only a purge
// releases a slot.
var ErrVaultQuotaExceeded = errors.New("vault provisioning quota exceeded")

// ErrPurgeProtectionNotPermitted means a quota-bounded caller tried to set
// purge_protection. Allowing it would let a grantee protect a vault,
// soft-delete it, and hold the quota slot forever, since PurgeVault refuses a
// protected vault and the purge scheduler honours the same flag. The guard is
// on quotaBounded specifically, not on "non-admin": a global-policy holder,
// who has no quota to pin, may still set purge_protection.
var ErrPurgeProtectionNotPermitted = errors.New("purge protection may only be set on a create that is not quota-bounded")

// CreateVaultProvisioned creates a vault, enforcing the caller's provisioning
// quota when quotaBounded is true and granting the caller full management
// rights over the vault it creates when grantCreatorRights is true. Both come
// from the caller's authz.CreateRight: admins pass both false; global-policy
// holders pass quotaBounded=false, grantCreatorRights=true (their global allow
// no longer covers the vault they just made -- see the design doc); a
// provisioning grant holder passes both true.
//
// Quota enforcement runs INSIDE the transaction that inserts the vault. A
// check outside it races the insert and the bound becomes advisory.
func (s *vaultService) CreateVaultProvisioned(ctx context.Context, req model.CreateVaultRequest, createdBy uuid.UUID, quotaBounded, grantCreatorRights bool) (*model.Vault, error) {
	if err := model.ValidateNewVaultName(req.Name); err != nil {
		return nil, err
	}
	if err := model.ValidateVaultTags(req.Tags); err != nil {
		return nil, err
	}
	if quotaBounded && req.PurgeProtection != nil && *req.PurgeProtection {
		return nil, ErrPurgeProtectionNotPermitted
	}

	// An admin caller is neither quota-bounded nor in need of creator grants:
	// the admin role short-circuits every authorization check, so grants for
	// it would be dead rows. Fall back to the pre-existing non-transactional
	// create, which needs no transaction wiring.
	if !quotaBounded && !grantCreatorRights {
		return s.CreateVault(ctx, req, createdBy)
	}
	// Anything else touches more than one table and MUST be transactional. If
	// the deps are not wired we refuse rather than silently creating a vault
	// with no quota check or no creator rights -- a guard that degrades to "no
	// guard" on a wiring mistake is worse than no guard at all, because it
	// looks like it is working.
	if s.txBeginner == nil {
		return nil, fmt.Errorf("vault creation cannot be completed: transaction support is not wired")
	}
	if quotaBounded && s.grantLocker == nil {
		return nil, fmt.Errorf("provisioning quota cannot be enforced: grant locking is not wired")
	}

	v := s.buildVault(req, createdBy)

	txRepo, ok := s.repo.(txCapableCreateRepo)
	if !ok {
		return nil, fmt.Errorf("vault repository does not support transactional create")
	}

	var count, quota int
	err := s.withTx(ctx, func(tx *db.Tx) error {
		if quotaBounded {
			var err error
			quota, err = s.grantLocker.LockAndReadQuotaTx(ctx, tx, createdBy)
			if err != nil {
				return err
			}
			count, err = txRepo.CountByCreatedBy(ctx, tx, createdBy)
			if err != nil {
				return err
			}
			if count >= quota {
				return fmt.Errorf("%w: %d of %d used", ErrVaultQuotaExceeded, count, quota)
			}
		}
		if err := txRepo.CreateTx(ctx, tx, v); err != nil {
			return err
		}
		if s.creatorGranter == nil {
			// A vault whose creator holds no rights over it is worse than a
			// refused create. For a quota-bounded caller it also permanently
			// occupies a quota slot, since only a purge (which that caller
			// cannot perform) frees one. Fail closed either way.
			return fmt.Errorf("creator grants cannot be written: grant support is not wired")
		}
		// The creator becomes full manager of what it created: vault-scoped
		// vaults:manage for lifecycle operations, and Key Vault Administrator
		// for the data plane. Both are scoped to this vault only -- a global
		// policy here would hand the grantee the instance.
		vaultID := v.ID
		if err := s.creatorGranter.CreatePolicyTx(ctx, tx, &model.AccessPolicy{
			ID:            uuid.New(),
			PrincipalID:   createdBy,
			PrincipalType: model.PrincipalTypeUser,
			ResourceType:  model.PolicyResourceVaults,
			Operation:     model.OpManage,
			Effect:        model.PolicyEffectAllow,
			VaultID:       &vaultID,
		}); err != nil {
			return fmt.Errorf("grant creator vault management: %w", err)
		}
		return s.creatorGranter.CreateRoleTx(ctx, tx, &model.RoleAssignment{
			ID:            uuid.New(),
			PrincipalID:   createdBy,
			PrincipalType: model.PrincipalTypeUser,
			Role:          model.RoleKeyVaultAdministrator,
			VaultID:       v.ID,
			CreatedBy:     createdBy,
		})
	})
	if err != nil {
		if errors.Is(err, ErrVaultQuotaExceeded) && s.log != nil {
			// A quota refusal is a security-relevant event -- record it the
			// same way a successful create is recorded below, not silently.
			s.log.LogAuditInfo(createdBy.String(), "create_vault", "denied",
				fmt.Sprintf("Vault creation refused: provisioning quota exceeded (%d of %d used)", count, quota))
		}
		return nil, err
	}
	if s.log != nil {
		// Three distinct callers reach vault creation, and each must be
		// distinguishable in the audit log: an admin create never reaches this
		// function (see the early return above) and is logged by CreateVault as
		// "Vault created: %s"; a provisioning-grant create is quota-bounded; a
		// global-policy create is neither admin nor quota-bounded, but -- unlike
		// admin -- it awards the creator Key Vault Administrator on this vault,
		// so it must not share admin's audit text.
		var detail string
		switch {
		case quotaBounded:
			detail = fmt.Sprintf("Vault created under provisioning grant: %s", v.Name)
		case grantCreatorRights:
			detail = fmt.Sprintf("Vault created under global vaults:manage grant (creator rights granted): %s", v.Name)
		default:
			// Unreachable: this function only runs when quotaBounded ||
			// grantCreatorRights. Kept as a safe fallback rather than silently
			// mislabeling an unexpected combination.
			detail = fmt.Sprintf("Vault created: %s", v.Name)
		}
		s.log.LogAuditInfo(createdBy.String(), "create_vault", "success", detail)
		// The creator-grant block above (CreatePolicyTx/CreateRoleTx) writes the
		// Key Vault Administrator assignment directly against the transaction,
		// bypassing RoleAssignmentService.AssignRole and the "assign_role" audit
		// entry every other path to acquiring that role produces. Without this,
		// a non-admin creator's self-acquired KVA over the vault it just made is
		// invisible next to every other way of getting it. Logged here -- after
		// withTx has already committed -- rather than inside the transaction
		// closure: LogAuditInfo's persister writes through its own DB handle, not
		// tx, so calling it from inside an open transaction risks lock
		// contention with it on SQLite, and would log a "success" for a role
		// grant that a future change to that closure could still roll back.
		// This mirrors how CreateVaultProvisioned's own "create_vault" entry
		// above, and RoleAssignmentService.AssignRole's "assign_role" entry, are
		// both already logged: after the write is durable, never inside it.
		s.log.LogAuditInfo(createdBy.String(), "assign_role", "success",
			fmt.Sprintf("Role %q assigned to principal %s in vault %s (vault creator grant)",
				model.RoleKeyVaultAdministrator, createdBy, v.ID))
	}
	return v, nil
}

// getByName reads a vault by name, normalizing a genuine not-found into
// ErrVaultNotFound while propagating any other repository error (e.g. a DB
// outage) unchanged, so callers can tell "vault doesn't exist" (404) apart
// from "the lookup itself failed" (500).
func (s *vaultService) getByName(ctx context.Context, name string) (*model.Vault, error) {
	if s.vaultCache != nil {
		if v, ok := s.vaultCache.Get(name); ok {
			return v, nil
		}
	}
	v, err := s.repo.ReadByName(ctx, name)
	if err != nil {
		if errors.Is(err, repositories.ErrNotFound) {
			return nil, fmt.Errorf("vault %q: %w", name, ErrVaultNotFound)
		}
		return nil, fmt.Errorf("get vault %q: %w", name, err)
	}
	if s.vaultCache != nil {
		s.vaultCache.Set(name, v)
	}
	return v, nil
}

// GetVault returns an active vault by name.
func (s *vaultService) GetVault(ctx context.Context, name string) (*model.Vault, error) {
	return s.getByName(ctx, name)
}

// ListVaults returns active vaults, optionally including soft-deleted ones.
func (s *vaultService) ListVaults(ctx context.Context, includeDeleted bool) ([]model.Vault, error) {
	vaults, err := s.repo.List(ctx)
	if err != nil {
		return nil, err
	}
	if includeDeleted {
		deleted, err := s.repo.ListDeleted(ctx)
		if err != nil {
			return nil, err
		}
		vaults = append(vaults, deleted...)
	}
	return vaults, nil
}

// ListVaultsScoped returns every vault when all is true (the admin and
// global-policy path, identical to ListVaults), and otherwise only vaults
// where principalID holds a vault-scoped vaults:manage allow.
//
// A policy-lookup error is propagated rather than swallowed into an empty
// list: an empty list is a positive claim ("you manage no vaults"), and a
// database outage reported that way would tell a caller their vaults are
// gone. Propagating discloses nothing about vaults the caller cannot see and
// is equally safe, but truthful. This differs from CanManageVault, which
// legitimately fails closed to a denial -- a denial carries no false
// information, but a listing does.
func (s *vaultService) ListVaultsScoped(ctx context.Context, principalID uuid.UUID, includeDeleted, all bool) ([]model.Vault, error) {
	if all {
		return s.ListVaults(ctx, includeDeleted)
	}
	if s.policyVaults == nil {
		return nil, nil
	}
	ids, err := s.policyVaults.ListVaultIDsForPrincipal(ctx, principalID)
	if err != nil {
		return nil, fmt.Errorf("list manageable vaults: %w", err)
	}
	if len(ids) == 0 {
		return nil, nil
	}
	allowed := make(map[uuid.UUID]struct{}, len(ids))
	for _, id := range ids {
		allowed[id] = struct{}{}
	}
	everything, err := s.ListVaults(ctx, includeDeleted)
	if err != nil {
		return nil, err
	}
	out := make([]model.Vault, 0, len(ids))
	for _, v := range everything {
		if _, ok := allowed[v.ID]; ok {
			out = append(out, v)
		}
	}
	return out, nil
}

// UpdateVault applies the non-nil request overrides to an active vault and persists it.
func (s *vaultService) UpdateVault(ctx context.Context, name string, req model.UpdateVaultRequest, updatedBy uuid.UUID) (*model.Vault, error) {
	v, err := s.getByName(ctx, name)
	if err != nil {
		return nil, err
	}
	if req.Enabled != nil {
		v.Enabled = *req.Enabled
	}
	if req.PurgeProtection != nil {
		v.PurgeProtection = *req.PurgeProtection
	}
	if req.RetentionDays != nil {
		v.RetentionDays = *req.RetentionDays
	}
	if req.Tags != nil {
		if err := model.ValidateVaultTags(*req.Tags); err != nil {
			return nil, err
		}
		v.Tags = *req.Tags
	}
	if updatedBy != uuid.Nil {
		v.UpdatedBy = &updatedBy
	}
	if err := s.repo.Update(ctx, v); err != nil {
		return nil, fmt.Errorf("update vault: %w", err)
	}
	if s.vaultCache != nil {
		s.vaultCache.Invalidate(name)
	}
	if s.log != nil {
		s.log.LogAuditInfo(updatedBy.String(), "update_vault", "success", fmt.Sprintf("Vault updated: %s", v.Name))
	}
	return v, nil
}

// DeleteVault soft-deletes a vault and cascades the soft-delete to its contents.
func (s *vaultService) DeleteVault(ctx context.Context, name string) error {
	if name == model.DefaultVaultName {
		return fmt.Errorf("the default vault cannot be deleted: %w", ErrDefaultVaultProtected)
	}
	v, err := s.getByName(ctx, name)
	if err != nil {
		return err
	}

	if s.txBeginner == nil {
		// No transaction support configured (e.g. unit tests against fakes);
		// fall back to the pre-existing non-transactional sequence.
		if err := s.repo.SoftDelete(ctx, v.ID); err != nil {
			return err
		}
		deleted, err := s.repo.ReadByID(ctx, v.ID)
		if err != nil {
			return fmt.Errorf("read vault after soft-delete: %w", err)
		}
		if deleted.DeletedAt == nil {
			return fmt.Errorf("vault %q missing deleted_at after soft-delete", name)
		}
		if err := s.cascade.SoftDeleteVaultContents(ctx, v.ID, *deleted.DeletedAt); err != nil {
			return fmt.Errorf("cascade soft-delete vault contents: %w", err)
		}
	} else {
		txRepo, ok := s.repo.(txCapableVaultRepo)
		if !ok {
			return fmt.Errorf("vault repository %T does not support transactional operations", s.repo)
		}
		// Soft-delete the vault row and cascade its contents atomically: if the
		// cascade fails partway, the whole transaction rolls back and the vault
		// row itself is never left soft-deleted without its contents following.
		if err := s.withTx(ctx, func(tx *db.Tx) error {
			if err := txRepo.SoftDeleteTx(ctx, tx, v.ID); err != nil {
				return err
			}
			deleted, err := txRepo.ReadByIDTx(ctx, tx, v.ID)
			if err != nil {
				return fmt.Errorf("read vault after soft-delete: %w", err)
			}
			if deleted.DeletedAt == nil {
				return fmt.Errorf("vault %q missing deleted_at after soft-delete", name)
			}
			if err := s.cascade.SoftDeleteVaultContentsTx(ctx, tx, v.ID, *deleted.DeletedAt); err != nil {
				return fmt.Errorf("cascade soft-delete vault contents: %w", err)
			}
			return nil
		}); err != nil {
			return err
		}
	}

	// The cascade soft-deleted this vault's secrets with a bulk UPDATE that
	// never went through CachedSecretService, so evict what it invalidated.
	s.flushSecretCache(ctx, v.ID, "vault delete")
	if s.vaultCache != nil {
		s.vaultCache.Invalidate(name)
	}

	if s.log != nil {
		s.log.LogAuditInfo("", "delete_vault", "success", fmt.Sprintf("Vault deleted: %s", name))
	}
	return nil
}

// RecoverVault restores a soft-deleted vault and cascades the recovery to its contents.
func (s *vaultService) RecoverVault(ctx context.Context, name string) error {
	v, err := s.findDeleted(ctx, name)
	if err != nil {
		return err
	}
	if v.DeletedAt == nil {
		return fmt.Errorf("vault %q missing deleted_at", name)
	}
	// Capture the vault's deletion timestamp before recovery clears it. The cascade
	// restores only the contents stamped with this exact timestamp, leaving rows the
	// user deleted individually (different deleted_at) untouched.
	deletedAt := *v.DeletedAt

	if s.txBeginner == nil {
		if err := s.repo.Recover(ctx, v.ID); err != nil {
			return fmt.Errorf("recover vault: %w", err)
		}
		if err := s.cascade.RecoverVaultContents(ctx, v.ID, deletedAt); err != nil {
			return fmt.Errorf("cascade recover vault contents: %w", err)
		}
	} else {
		txRepo, ok := s.repo.(txCapableVaultRepo)
		if !ok {
			return fmt.Errorf("vault repository %T does not support transactional operations", s.repo)
		}
		if err := s.withTx(ctx, func(tx *db.Tx) error {
			if err := txRepo.RecoverTx(ctx, tx, v.ID); err != nil {
				return fmt.Errorf("recover vault: %w", err)
			}
			if err := s.cascade.RecoverVaultContentsTx(ctx, tx, v.ID, deletedAt); err != nil {
				return fmt.Errorf("cascade recover vault contents: %w", err)
			}
			return nil
		}); err != nil {
			return err
		}
	}

	// The cascade cleared deleted_at on this vault's secrets outside the cache
	// layer; flush so no entry admitted during the deleted window survives.
	s.flushSecretCache(ctx, v.ID, "vault recover")
	if s.vaultCache != nil {
		s.vaultCache.Invalidate(name)
	}

	if s.log != nil {
		s.log.LogAuditInfo("", "recover_vault", "success", fmt.Sprintf("Vault recovered: %s", name))
	}
	return nil
}

// PurgeVault permanently removes a vault, refusing the default and purge-protected vaults.
func (s *vaultService) PurgeVault(ctx context.Context, name string) error {
	if s.globalPurgeProtection {
		return fmt.Errorf("vault %q: %w", name, model.ErrGlobalPurgeProtectionEnabled)
	}
	if name == model.DefaultVaultName {
		return fmt.Errorf("the default vault cannot be purged: %w", ErrDefaultVaultProtected)
	}

	// Normally a vault is purged after a soft-delete, so check there first.
	v, err := s.findDeleted(ctx, name)
	if err != nil {
		if !errors.Is(err, ErrVaultNotFound) {
			// findDeleted failed for a reason other than "no match" (e.g. the
			// underlying ListDeleted call hit a DB error) -- don't mask it by
			// falling through to a second lookup.
			return err
		}
		// Fall back to an active vault when no soft-deleted match exists.
		v, err = s.getByName(ctx, name)
		if err != nil {
			return err
		}
	}
	if v.PurgeProtection {
		return fmt.Errorf("vault %q is protected from purge: %w", name, ErrVaultPurgeProtected)
	}
	// Fail closed: if the check itself errors, refuse the purge rather than
	// risk bypassing an item's own protection because its status couldn't be
	// read (same posture as the vault-level PurgeProtection read).
	protected, err := s.cascade.HasProtectedContent(ctx, v.ID)
	if err != nil {
		return fmt.Errorf("check vault %q contents for purge protection: %w", name, err)
	}
	if protected {
		return fmt.Errorf("vault %q contains items protected from purge: %w", name, ErrVaultContentsPurgeProtected)
	}
	if err := s.repo.Purge(ctx, v.ID); err != nil {
		return err
	}
	if s.vaultCache != nil {
		s.vaultCache.Invalidate(name)
	}
	// Secrets, keys, and certificates have no FK on vault_id either -- purge
	// their rows explicitly for the same reason access_policies' are purged
	// below, or they'd be stranded permanently, unreachable but never removed.
	if err := s.cascade.PurgeVaultContents(ctx, v.ID); err != nil {
		return fmt.Errorf("purge vault contents: %w", err)
	}
	// access_policies has no FK to vaults, so vault-scoped policy rows must be
	// removed explicitly to avoid orphaning them after the vault is purged.
	if s.policies != nil {
		if err := s.policies.DeleteByVault(ctx, v.ID); err != nil {
			return fmt.Errorf("delete vault policies: %w", err)
		}
	}
	// role_assignments declares ON DELETE CASCADE on vault_id, but the SQLite
	// foreign_keys pragma is off here, so the cascade is inert and the rows
	// must be removed explicitly -- same reason as the access_policies block
	// above.
	if s.roleAssignments != nil {
		if err := s.roleAssignments.DeleteByVault(ctx, v.ID); err != nil {
			return fmt.Errorf("delete vault role assignments: %w", err)
		}
	}
	// vault_webhook_configs' ON DELETE CASCADE is inert on SQLite (the
	// foreign_keys PRAGMA is off here), so the row must be removed explicitly
	// or it strands an encrypted signing secret for a vault that no longer
	// exists.
	if s.webhooks != nil {
		if err := s.webhooks.DeleteByVaultID(ctx, v.ID); err != nil {
			return fmt.Errorf("purge vault webhook config: %w", err)
		}
	}
	if s.log != nil {
		s.log.LogAuditInfo("", "purge_vault", "success", fmt.Sprintf("Vault purged: %s", name))
	}
	return nil
}

// findDeleted returns the soft-deleted vault with the given name, or an error if none exists.
func (s *vaultService) findDeleted(ctx context.Context, name string) (*model.Vault, error) {
	deleted, err := s.repo.ListDeleted(ctx)
	if err != nil {
		return nil, err
	}
	for i := range deleted {
		if deleted[i].Name == name {
			return &deleted[i], nil
		}
	}
	return nil, fmt.Errorf("vault %q: %w", name, ErrVaultNotFound)
}
