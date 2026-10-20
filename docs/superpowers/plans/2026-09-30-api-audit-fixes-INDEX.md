# API audit fixes: plan index

**Source**: 2026-09-30 audit of `api/` (static read, not reproduced live). GitHub issues #40-#50,
plus two High findings that have no issue yet (OIDC MFA gap, restore-blob renewal chain).
Research doc for the OIDC finding: `.claude/research-oidc-user-mfa-enrollment.md`.

**Status**: plans only. Nothing implemented, nothing committed. Plan code was written from reading
source and has not been compiled, except parts of the authorization plan that a verifier ran in a
scratchpad copy. A verifier checked all five plans' citations on 2026-09-30 and four were corrected.

## Plans

| Plan | Tasks | Issues | B-numbers |
|---|---|---|---|
| [identity-sessions-hardening](2026-09-30-identity-sessions-hardening.md) | 13 (13 optional) | #40, OIDC MFA core, #47, #45 | B72-B75 |
| [certificate-restore-renewal-isolation](2026-09-30-certificate-restore-renewal-isolation.md) | 11 | restore-blob chain, #43 | B76-B78 |
| [authorization-policy-and-audit](2026-09-30-authorization-policy-and-audit.md) | 13 | #42, #50, #49 | B79-B81 |
| [secrets-and-error-responses](2026-09-30-secrets-and-error-responses.md) | 12 | #41 (with B55), #44, #48 | B82-B84 |
| [login-rate-limiting](2026-09-30-login-rate-limiting.md) | 8 | #46 | B85 |

## Hard ordering rules

- Identity before login rate limiting. Identity adds two new failure exits to `AuthenticateUser`
  that rate limiting must also record.
- Authorization before certificates. The certificate plan replaces
  `internal/services/authorization/data_action_authz.go` wholesale and must rebase its test edits
  onto the authorization plan's edit at `data_action_authz_test.go:33`.

## Proposed merge order (awaiting decision)

1. Identity (P1)
2. Authorization
3. Certificates (P1)
4. Secrets
5. Login rate limiting

The alternative considered puts secrets first (it is self-contained): secrets, authorization,
identity, rate limiting, certificates. The tradeoff is that the two P1 fixes land later.

## Known manual merges

- `writeCertificateError` (`api/errors_certificate.go`): the secrets plan adds an `ErrNameTaken`
  arm, the certificate plan adds five more. The second to land merges into the switch.
- `api/users.go` import block (identity and rate limiting), `internal/db/db.go` schema and
  migrations, `internal/container/service_container.go`, `.claude/known-bugs.md` and
  `scripts/docsgen/docs.go` (all five plans touch them).
- Line numbers in every plan drift as earlier plans land. Re-anchor by symbol, not line.

## Open decisions

1. Merge order (above).
2. Release-note versions are guessed and collide: secrets v4.6.1; identity, authorization and rate
   limiting all v4.7.0; certificates v4.8.0. Assign one unique version per plan once the order is
   fixed.
3. Breaking change in the certificate plan: Key Vault Certificates Officer alone can no longer
   issue certificates (also needs Key Vault Crypto User), and auto-renew stops for owners without
   `keys/sign`. Accept, or add a compatibility path?
4. Identity plan defers the fresh-login requirement and pending TOTP enrollment (research doc
   open questions 2 and 3).
5. Authorization plan leaves one gap: `POST /{resource}/restore` still resolves to `OpRecover`,
   so an explicit deny on `restore` is not checked over HTTP (recorded as not fixed in B79).
6. Three plans create GitHub issues at run time with `gh issue create` (identity B73, certificates
   B76 and B78).
7. `golangci-lint` cannot run in this environment (snap Go toolchain incompatibility), so lint
   must run in CI or on a fixed toolchain before any PR.
