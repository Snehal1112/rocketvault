# Security Incident: Config Files with Secrets in Git History

**Date:** 2026-03-07
**Branch:** fix/architecture-review-2026-03-07

## What happened

Four config files containing `master_key`, `jwt_secret`, and `bootstrap_token`
in plaintext were tracked in git history:

- `.rocketvault.yaml`
- `.rocketvault-production.yaml`
- `.rocketvault-staging.yaml`
- `.rocketvault-test.yaml`

## Immediate actions taken

- All four files removed from git tracking (`git rm --cached`)
- `.rocketvault*.yaml` added to `.gitignore`

## OPERATOR ACTION REQUIRED

### 1. Rotate all secrets immediately

Generate new values and update your local config files:

```bash
# New master_key (32 bytes, base64)
openssl rand -base64 32

# New jwt_secret (32 bytes, base64)
openssl rand -base64 32

# New bootstrap_token (32 bytes, base64)
openssl rand -base64 32
```

### 2. Purge secrets from git history

Install git-filter-repo if needed: `pip install git-filter-repo`

```bash
git filter-repo \
  --path .rocketvault.yaml \
  --path .rocketvault-production.yaml \
  --path .rocketvault-staging.yaml \
  --path .rocketvault-test.yaml \
  --invert-paths
```

### 3. Force-push and coordinate with collaborators

All collaborators must re-clone or reset their local repos after the
force-push, as their local history will diverge.

---

## Addendum (2026-08-16): this fix regressed one day later

The `.gitignore` entry added by this incident's fix
(`.password-manager*.yaml`) never covered the project's next name — commit
`5dd5490`, the very next day, renamed the project to RocketVault and
introduced a new `.rocketvault.yaml` that this pattern didn't match. It stayed
tracked and unrotated for over five months until a 2026-08-16 penetration test
found it again. Full root-cause and fix:
`docs/known-bugs.md` § B10,
`docs/superpowers/specs/2026-08-16-secrets-in-git-remediation-design.md`.

The lesson that fix draws from this one: a `.gitignore` pattern change with no
test proving it matches, and no CI backstop catching a future miss, is not a
durable fix. Both gaps are closed this time — see the CI guard described in
the documents above.
