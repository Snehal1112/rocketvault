# OIDC JIT provisioning policy

## What

Add an admin-controlled policy to OIDC login so that RocketVault decides who may
be provisioned or may log in, instead of accepting every identity the issuer
authenticates. Fix the related OIDC gaps from Phase 0 section 2: no PKCE, an
ignored `email_verified` claim, email not stored on the user, lookup errors that
fall through to create, and a non-constant-time state compare.

## Why

Today anyone with an account at the configured issuer gets a `user` on first
login, and any lookup error (including a database error) creates a new user.
That blocks hosting a single-tenant instance, where the issuer may be a shared
or public identity provider.

## Scope

- New `oidc.*` policy keys with startup validation. JIT is off by default
  (`oidc.jit_enabled: false`), so an upgrade denies new identities until an admin
  opts in. Existing linked users still log in.
- Policy check in `FindOrCreateExternalUser`, run on every login.
- Sentinel `ErrExternalUserNotAllowed` mapped to a generic 403, with audit events
  `oidc_login_denied` and `oidc_user_provisioned`.
- Split not-found from database error in `ReadByExternalSubject`.
- Parse `email_verified`, store email on the user (migration).
- PKCE S256 and constant-time state compare.

## Out of scope

- Group or role claim mapping to roles beyond `oidc.default_role`.
- Shared CLI exchange store for multiple replicas (Phase 5).
- Audit reliability work (separate Phase 0 sub-project). Audit events here use
  the existing `LogAudit*` calls until `RecordCritical` exists.
