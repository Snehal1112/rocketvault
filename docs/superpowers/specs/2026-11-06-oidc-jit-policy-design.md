# OIDC JIT policy design

Date: 2026-11-06. Intent: `docs/superpowers/intents/2026-11-06-oidc-jit-policy.md`.
Source: Phase 0 section 2 of the SaaS roadmap (`docs/internal/saas-roadmap/phase-0-hardening.md`).

## Goal

Let an admin control who may be provisioned or may log in through OIDC, and fix the
related gaps: no PKCE, ignored `email_verified`, email not stored, lookup errors that
fall through to create, and a non-constant-time state compare.

## Decisions

- JIT is off by default. An upgrade denies new identities until an admin opts in.
  Already-linked users still log in.
- A user who fails the policy on a later login is denied (403) and keeps the account,
  grants and data.
- PKCE S256 is always on, with no config key.
- Identities link only by `(provider, subject)`. An email is never used to link or
  match an account.
- The policy lives in the user service (`ExternalUserPolicy`), so every caller of
  `FindOrCreateExternalUser` is covered.

## Config

Keys under `oidc:`, validated at startup in `internal/container/service_container.go`.

| Key | Default | Rule |
|---|---|---|
| `jit_enabled` | `false` | Controls creation of new users only. |
| `allowed_email_domains` | empty | Lowercase exact match on the part after `@`. When set, a verified email is required. |
| `require_email_verified` | `false` | Denies unless `email_verified` is true. |
| `required_claims` | empty | Claim name to expected string. Exact match, or membership when the claim is an array. An absent claim is denied. |
| `default_role` | `user` | Any other value fails startup. |
| `enforce_on_existing` | `true` | Applies domain, verified and required-claims checks to linked users on every login. |

Startup also fails on a malformed domain or an empty `required_claims` key.

## Policy evaluation

`ExternalUserPolicy.Evaluate(identity, isNew) error` is a pure function that returns
`ErrExternalUserNotAllowed`.

1. `isNew && !jit_enabled`: deny.
2. Domain, verified and required-claims checks. They always apply to new users and
   apply to existing users only when `enforce_on_existing` is true.
3. A missing or empty email is denied when a domain list is set. Email comparison is
   case-insensitive.

The denial reason goes to the audit event only. The client sees a generic 403.

## Identity changes

`OIDCIdentity` (`internal/services/auth/oidc_service.go`) gains `EmailVerified bool` and
`Claims map[string]any`. Raw claims are decoded once from the verified token.
`email_verified` accepts a bool or the string `"true"`.

## `FindOrCreateExternalUser` flow

1. Look up by `(provider, subject)`.
   - Found: if `enforce_on_existing`, run `Evaluate(identity, false)`; on denial
     return the sentinel. Otherwise refresh the stored email and return the user.
   - `errors.Is(err, ErrNotFound)`: go to step 2.
   - Any other error: return it wrapped. Nothing is created. The handler returns 500.
2. For a new user run `Evaluate(identity, true)`. On denial return the sentinel.
   Otherwise create the user with `default_role` and the email. The existing
   username-collision retry stays.

`FindOrCreateExternalUserRequest` gains `Email`, `EmailVerified` and `Claims`.
`api/oidc.go` passes them from `OIDCIdentity`.

## Audit

- `oidc_login_denied`: subject, provider and a reason code (`jit_disabled`, `domain`,
  `email_unverified`, `claim`). Never claim values.
- `oidc_user_provisioned`: user ID and role.
- Both use the existing `LogAudit*` calls. They convert to `RecordCritical` when the
  audit reliability sub-project lands.

## Storage

- Add a nullable `users.email` column in both `CREATE TABLE` and `migrateSchema`
  (`internal/db/db.go`), compatible with SQLite and Postgres.
- Add `Email` to `model.User` and to the user repository scan and insert.
- No unique index. Only OIDC logins write it. Local users keep it null.

## HTTP mapping (`api/oidc.go`)

- Sentinel: generic 403 `access denied`.
- Lookup or create error: 500.
- Token exchange failure: 401, unchanged.

## PKCE and state

- The login handler generates a 32-byte base64url `code_verifier` and stores it in an
  `oidc_pkce` cookie set through `setOIDCCookie`.
- `AuthCodeURL` adds the S256 challenge (`oauth2.S256ChallengeOption`).
- The callback reads the cookie (400 if missing) and passes the verifier to
  `HandleCallback`, which exchanges with `oauth2.VerifierOption`.
- State, nonce, PKCE and CLI cookies are cleared after the callback on every path.
- The state compare at `api/oidc.go:121` uses `subtle.ConstantTimeCompare`.

## Testing

- `Evaluate`: table covering JIT on/off, domain (case, missing email), verified (bool
  and string), required claims (scalar, array, absent), new vs existing, and
  `enforce_on_existing` on/off.
- `FindOrCreateExternalUser` with a stub repo: not-found creates; a DB error returns an
  error and creates nothing; a denial returns the sentinel; an existing user is
  re-checked; email is refreshed.
- Config validation failures listed above.
- Handler tests: 403 on the sentinel, 500 on a DB error, 400 on a missing PKCE cookie,
  verifier reaches the exchange.
- Migration: the column exists on both dialects and a second run is safe.

## Docs and tracking

- Add the keys to `.rocketvault.yaml.example` and `docs/contributing/configuration.md`.
- Release notes state that JIT is now off by default.
- File `known-bugs.md` entries and GitHub issues for: OIDC has no PKCE; OIDC ignores
  `email_verified` and provisions on any lookup error.

## Out of scope

Group or role claim mapping beyond `default_role`; the shared CLI exchange store
(Phase 5); audit reliability work.
