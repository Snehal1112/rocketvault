import type { Suite } from "./types"

export const journeysAF: Suite[] = [
  {
    key: "A",
    title: "Day zero: the admin discovers she has no access",
    actor: "Priya — global role admin",
    premise:
      "Creating a vault is a management operation. Everything inside it is not. The admin who just created `prod` cannot read a thing in it until she grants herself a role, because `HasDataAction` has no admin short-circuit by design.",
    cases: [
      {
        id: "A1",
        title: "Bootstrap the first admin with the one-time token",
        surface: "cli",
        gate: "none",
        precondition:
          "A clean instance with no users. The bootstrap token comes from your own `.rocketvault.yaml` — it is generated per clone, never committed.",
        command: `rocketvault users admin \\
  --admin-username priya \\
  --admin-password '<pw>' \\
  --bootstrap-token '<token-from-config>'`,
        expected: "The TOTP secret is printed exactly once. Capture it now.",
        assert: "Succeeds with no prior session; prints TOTP secret once",
        notes:
          "This is the only command that needs no session. Losing the printed secret means recreating the user.",
      },
      {
        id: "A2",
        title: "Log in and cache the session",
        surface: "cli",
        gate: "none",
        command: `rocketvault users login --username priya --password '<pw>' --totp-code "$TOTP_CODE"`,
        expected: "Login successful as priya.",
        assert: "Session cached under ~/.rocketvault/sessions",
        notes:
          "Every later CLI command picks this up with no credential flags. HTTP does **not** read this cache — curl needs its own token.",
      },
      {
        id: "A3",
        title: "Create the three vaults; the name is positional",
        surface: "cli",
        gate: "management",
        command: `rocketvault vaults create dev
rocketvault vaults create staging
rocketvault vaults create prod --purge-protection --retention-days 30`,
        expected: "Three vaults created.",
        assert: "Positional name accepted; no --vault flag exists here",
        notes:
          "`vaults create/delete/recover/purge/update` all take the name positionally. Passing `--vault` instead is a common early mistake.",
      },
      {
        id: "A4",
        title: "List and inspect the new vaults",
        surface: "cli",
        gate: "management",
        command: `rocketvault vaults list
rocketvault vaults get prod --output json`,
        expected:
          "`prod` reports purge protection enabled and 30-day retention.",
        assert: "Creation flags round-trip into the stored record",
        verify: {
          look: "The JSON keys are exactly `PurgeProtection` and `RetentionDays` — PascalCase, no hyphens or underscores. The CLI's JSON formatter uses each command's table headers verbatim as keys, and headers are chosen independently per command, so casing is not consistent across commands. `PurgeProtection` reads `true` and `RetentionDays` reads `30`.",
        },
        source: "cmd/vaults/get.go:55; internal/formatter/json.go:10-24",
      },
      {
        id: "A5",
        title: "Update only the attributes actually passed",
        surface: "cli",
        gate: "management",
        command: `rocketvault vaults update staging --retention-days 14
rocketvault vaults update staging --purge-protection`,
        expected:
          "Retention becomes 14 on the first call; purge protection turns on in the second, with retention still 14.",
        assert: "An omitted flag leaves its field unchanged",
        notes:
          "This is a partial update, unlike `keys rotation-policy set`, which is a full replace. The two behave differently on purpose.",
      },
      {
        id: "A6",
        title: "preview-migration refuses to run against a remote server",
        surface: "cli",
        gate: "management",
        precondition: "Only relevant when upgrading a pre-P2 install.",
        command: `rocketvault vaults preview-migration --server https://vault.prod.internal`,
        expected: "Refused — it reads the local database file directly.",
        assert: "Rejects --server rather than guessing",
        notes:
          "It writes nothing. Confirm every principal that needs access appears in its output **before** running the real migration, not after.",
      },
      {
        id: "A7",
        title: "The vault's own creator is denied inside it",
        surface: "cli",
        gate: "vault-role",
        precondition:
          "Priya has created `prod` and holds no role assignment in it.",
        command: `rocketvault keys list --vault prod`,
        expected:
          "Error: forbidden: no role grants Microsoft.KeyVault/vaults/keys/read in this vault",
        assert: "Denied — global admin does not bypass the vault check",
        flag: "trap",
        notes:
          "The single most surprising behaviour in RocketVault, and correct. Retract any runbook that says admin bypasses vault checks.",
        why: "`HasDataAction` looks up the principal's role assignments in the target vault and grants only if one of them includes the requested action; it never checks the caller's global account role. Creating a vault is a management decision (`CanManageVault`), and it writes no role assignment for the vault's creator, so a brand-new vault's own admin starts with zero data-plane access inside it.",
        related: [{ id: "A10", rel: "contrasts" }],
        source:
          "VAULT_USER_ACCESS_JOURNEYS_v3.md § Journey A — Day Zero: the admin discovers she has no access; internal/services/authorization/role_assignment_service.go:213",
      },
      {
        id: "A8",
        title: "The same denial over HTTP",
        surface: "http",
        gate: "vault-role",
        command: `curl -s -o /dev/null -w '%{http_code}\\n' $BASE/vaults/prod/secrets \\
  -H "Authorization: Bearer $ADMIN_TOKEN"`,
        expected: "403",
        assert: "403, not 404 and not 200",
        notes:
          "Both doors agree here. Journeys K and P are where they stop agreeing.",
      },
      {
        id: "A9",
        title: "Self-grant Key Vault Administrator in each vault",
        surface: "cli",
        gate: "management",
        command: `rocketvault vault-access grant priya --role "Key Vault Administrator" --vault prod
rocketvault vault-access grant priya --role "Key Vault Administrator" --vault dev
rocketvault vault-access grant priya --role "Key Vault Administrator" --vault staging`,
        expected: "Three assignments created, each with its own id.",
        assert: "Grant succeeds and returns an assignment id",
      },
      {
        id: "A10",
        title: "The denied command now works",
        surface: "cli",
        gate: "vault-role",
        command: `rocketvault keys list --vault prod`,
        expected: "An empty list, not a forbidden error.",
        assert: "Same command as A7, now permitted",
        notes:
          "Put “self-grant Key Vault Administrator in every new vault” in your provisioning runbook, or the vault is unusable to whoever created it.",
        why: "Once `vault-access grant priya --role \"Key Vault Administrator\" --vault prod` creates a role assignment, `HasDataAction`'s lookup of Priya's assignments in `prod` finds one whose bundle grants every data action — including the key-read action `keys list` checks — where A7's identical lookup found nothing.",
        related: [{ id: "A9", rel: "depends" }],
        source:
          "internal/services/authorization/role_assignment_service.go:213; model/azure_roles.go (RoleKeyVaultAdministrator bundle)",
      },
      {
        id: "A11",
        title: "Create the team with the global roles the CLI requires",
        surface: "cli",
        gate: "global-admin",
        command: `rocketvault users create --new-username wren   --new-password '<pw>' --new-role user
rocketvault users create --new-username sofia  --new-password '<pw>' --new-role crypto_manager
rocketvault users create --new-username marcus --new-password '<pw>' --new-role secrets_manager
rocketvault users create --new-username daeho  --new-password '<pw>' --new-role user
rocketvault users create --new-username ops-oncall --new-password '<pw>' --new-role admin`,
        expected: "Each command prints a TOTP secret exactly once.",
        assert: "Five users created; five TOTP secrets captured",
        notes:
          "Capture every secret as it appears. The rest of this playbook cannot be run without them.",
        why: "Every mutating `keys`/`secrets`/`certificates` CLI command checks the caller's global account role — `admin` or the matching manager role — before the vault-scoped data action, and HTTP has no equivalent check. Sofia, Marcus and Noor are given `crypto_manager`, `secrets_manager` and `certificate_manager` here specifically so their CLI sessions can pass that check in the journeys that follow; a `user` role holding the matching vault role would still be refused by the CLI alone.",
        source:
          "VAULT_USER_ACCESS_JOURNEYS_v3.md § Correction 8 — The CLI enforces a global role gate the HTTP path does not; § Corrected Cast",
      },
      {
        id: "A12",
        title: "--new-role is repeatable, not comma-separated",
        surface: "cli",
        gate: "validation",
        command: `rocketvault users create --new-username multi --new-password '<pw>' \\
  --new-role admin --new-role secrets_manager`,
        expected: "A user holding both roles.",
        assert: "Two --new-role flags produce two roles",
        notes:
          "`--new-role admin,secrets_manager` does not split into two roles. Check what actually landed with `users list --output json`.",
        why: '`--new-role` is registered as a cobra `StringArray` flag, not `StringSlice` — `StringArray` takes each flag occurrence as one literal value and never splits on commas. `--new-role admin,secrets_manager` becomes a single role string `"admin,secrets_manager"`, not two roles; only repeating the flag produces two.',
        verify: {
          command:
            "rocketvault users list --output json | jq '.[] | select(.Username==\"multi\") | .Role'",
          look: "The CLI's JSON output uses each command's table headers verbatim as keys, so the field is `Role` (capitalized), not `roles`, and its value is the comma-joined string `admin, secrets_manager` — both role names present. A single `--new-role` occurrence would show only one name here.",
        },
        source:
          'cmd/users/create.go:151; cmd/users/list.go (headers `["ID", "Username", "Role", "Created"]`, built via `strings.Join(u.Roles, ", ")`); internal/formatter/json.go:10-24',
      },
    ],
  },
  {
    key: "B",
    title: "Onboarding a backend engineer, one role at a time",
    actor: "Marcus — global role secrets_manager",
    premise:
      "Reader, then Secrets User, then Secrets Officer. Each step should unlock exactly one more thing and nothing else, and none of them should reach `prod`.",
    cases: [
      {
        id: "B1",
        title: "Week 1: Reader sees metadata",
        surface: "cli",
        gate: "vault-role",
        precondition: `rocketvault vault-access grant marcus --role "Key Vault Reader" --vault dev`,
        command: `rocketvault secrets list --vault dev`,
        expected: "The list renders — names, tags, timestamps.",
        assert: "Listing works under Reader",
      },
      {
        id: "B2",
        title: "Reader cannot read a secret value",
        surface: "cli",
        gate: "vault-role",
        command: `rocketvault secrets get <secret-id> --vault dev`,
        expected: "Error: forbidden — Reader has no secrets/get",
        assert: "Denied; Reader holds readMetadata, not secrets/get",
        related: [{ id: "B5", rel: "contrasts" }],
      },
      {
        id: "B3",
        title: "Reader must not see values in the versions list",
        surface: "http",
        gate: "vault-role",
        precondition:
          "This is the § B30 regression check. Run it on every release.",
        command: `curl -s $BASE/vaults/dev/secrets/<secret-id>/versions \\
  -H "Authorization: Bearer $MARCUS_TOKEN" | jq '[.versions[] | has("value")] | any'`,
        expected: "false",
        assert: "Prints exactly false",
        flag: "trap",
        notes:
          "A `true` here means secret values are leaking to a metadata-only role through the versions endpoint. Treat it as a release blocker, not a bug report.",
        why: "`GET /secrets/{id}/versions` used to map to `ActionSecretsReadMetadata` — an action Reader holds — while still decrypting and returning every version's value, because `model.SecretVersion` carried a `Value` field with no metadata-only counterpart. The fix introduced `model.SecretVersionMetadata`, which has no `Value` field at all, so the handler now has nothing to leak even by a future mistake.",
        related: [{ id: "B1", rel: "depends" }],
        source:
          "docs/known-bugs.md § B30 — A Key Vault Reader can dump every historical plaintext value of every secret in a vault",
      },
      {
        id: "B4",
        title: "Week 2: swap Reader for Secrets User",
        surface: "cli",
        gate: "management",
        command: `rocketvault vault-access revoke <reader-assignment-id> --vault dev
rocketvault vault-access grant marcus --role "Key Vault Secrets User" --vault dev`,
        expected: "The Reader assignment is gone; a Secrets User one exists.",
        assert: "Revoke then grant both succeed",
      },
      {
        id: "B5",
        title: "Secrets User can now read the value",
        surface: "cli",
        gate: "vault-role",
        command: `rocketvault secrets get <secret-id> --vault dev --output json`,
        expected: "The response carries the decrypted value.",
        assert: "Value returned — the same call that failed in B2",
      },
      {
        id: "B6",
        title: "Secrets User still cannot write",
        surface: "cli",
        gate: "vault-role",
        command: `rocketvault secrets create test-db-pass 's3cr3t' --vault dev`,
        expected: "Error: forbidden (no secrets/set)",
        assert: "Denied at the vault-role gate, not the global-role gate",
        why: "Marcus holds `secrets_manager` globally, so Correction 8's CLI-only global-role gate passes cleanly. `secrets create` also needs the vault-scoped `Microsoft.KeyVault/vaults/secrets/setSecret/action`, and Key Vault Secrets User's bundle grants only `readMetadata` and `getSecret` — no `setSecret` — so `HasDataAction` denies it regardless of his global role.",
        related: [{ id: "B4", rel: "depends" }],
        source:
          "VAULT_USER_ACCESS_JOURNEYS_v3.md § Correction 8; § Corrected Cast; model/azure_roles.go (RoleKeyVaultSecretsUser bundle)",
      },
      {
        id: "B7",
        title: "Month 3: Secrets Officer writes, updates and filters",
        surface: "cli",
        gate: "vault-role",
        precondition: `rocketvault vault-access grant marcus --role "Key Vault Secrets Officer" --vault dev`,
        command: `rocketvault secrets create db-pass 's3cr3t-v1' --tags prod,db --vault dev
rocketvault secrets update <secret-id> 's3cr3t-v2' --vault dev
rocketvault secrets list --vault dev --tags prod --output json`,
        expected: "Create and update succeed; the tag filter returns db-pass.",
        assert: "Full secret ownership in dev",
        why: "Key Vault Secrets Officer's bundle adds `setSecret`, `delete`, `backup`, `restore`, `recover` and `purge` on top of the same `readMetadata`/`getSecret` pair Secrets User already held — the write and lifecycle actions B6 found missing.",
        related: [{ id: "B6", rel: "contrasts" }],
        source:
          "model/azure_roles.go (RoleKeyVaultSecretsOfficer / RoleKeyVaultSecretsUser bundles)",
      },
      {
        id: "B8",
        title: "Still nothing in prod",
        surface: "cli",
        gate: "vault-role",
        command: `rocketvault secrets list --vault prod`,
        expected: "Error: forbidden: no role grants ... in this vault",
        assert: "Three grants in dev buy nothing in prod",
        why: "Role assignments are stored per vault, and `HasDataAction` looks them up with `ListByPrincipalInVault(principalID, vaultID)`. A lookup scoped to `prod` finds none of the three `dev` grants, because none of them was ever written against `prod`'s vault id.",
        source:
          "internal/services/authorization/role_assignment_service.go:213-221",
      },
      {
        id: "B9",
        title: "Re-granting the same role is harmless",
        surface: "cli",
        gate: "management",
        command: `rocketvault vault-access grant marcus --role "Key Vault Secrets Officer" --vault dev`,
        expected: "The original assignment id is returned, not a new one.",
        assert: "Idempotent — no duplicate row, no error",
        notes: "Safe to put in a provisioning script that may re-run.",
        why: "`AssignRole` looks up the assignment by its `(principal, role, vault)` tuple via `FindByTuple` before creating one, and returns the existing row unchanged when a match exists instead of inserting a duplicate or erroring.",
        source:
          "internal/services/authorization/role_assignment_service.go:114-145",
      },
      {
        id: "B10",
        title: "A user can read and update their own account",
        surface: "cli",
        gate: "global-admin",
        command: `rocketvault users get <marcus-user-id>
rocketvault users update <marcus-user-id> --new-password 'new-Str0ng-pw'`,
        expected: "Both succeed — owner-or-admin, with no vault scoping.",
        assert: "Own profile is readable and writable",
        notes:
          "User accounts are global. There is no vault-scoped user, so `--vault` does nothing here.",
        why: "User accounts carry no `vault_id`. `users get`/`update` check only `claims.UserID != id` plus the global `admin` role — there is no vault-scoped lookup for a `--vault` flag to filter on, which is why passing one here does nothing.",
        source: "cmd/users/get.go:71-73; cmd/users/update.go:76-80",
      },
      {
        id: "B11",
        title: "A user cannot read someone else's account",
        surface: "cli",
        gate: "global-admin",
        command: `rocketvault users get <sofia-user-id>`,
        expected:
          "Error: forbidden: can only access your own profile or requires admin role",
        assert: "Denied on another principal's record",
        why: "The same `claims.UserID != id` check that let B10 pass denies here: Marcus's ID does not match Sofia's, and he holds no `admin` role to satisfy the fallback.",
        source: "cmd/users/get.go:71-73",
      },
      {
        id: "B12",
        title: "A user cannot grant themselves a global role",
        surface: "cli",
        gate: "global-admin",
        command: `rocketvault users update <marcus-user-id> --new-role admin`,
        expected: "Error: forbidden: only admins can change roles",
        assert: "Self-escalation blocked even on your own record",
        flag: "trap",
        notes:
          "Note the shape: he *can* update his own record, but not that field of it. A test asserting only “update succeeds” would miss this.",
        why: "The role-change guard runs twice: `cmd/users/update.go` refuses any `--new-role` when the caller lacks the `admin` role, and `UserService.UpdateUser` repeats the identical check before writing — a defense-in-depth pair that blocks self-promotion even though the same command's non-role fields (B10) are owner-writable.",
        source:
          "cmd/users/update.go:93-98; internal/services/users/user_service.go:248-254",
      },
    ],
  },
  {
    key: "C",
    title: "Security engineer owns the key lifecycle",
    actor: "Sofia — global role crypto_manager",
    premise:
      "Every mutating `keys` command needs `admin` or `crypto_manager` globally, on top of the vault role. This journey walks create, sign, verify, update, rotate and rotation policy, and ends at three capabilities that do not exist.",
    cases: [
      {
        id: "C1",
        title: "Create an RSA key with tags and purge protection",
        surface: "cli",
        gate: "global-role",
        precondition: `rocketvault vault-access grant sofia --role "Key Vault Crypto Officer" --vault prod`,
        command: `rocketvault keys create --name payments-signing --type RSA --bits 4096 \\
  --tags prod,jwt --purge-protection --vault prod`,
        expected: "The key is created and its id printed.",
        assert: "Create succeeds with crypto_manager + Crypto Officer",
        why: "`keys create` runs Correction 8's global-role check (`admin` or `crypto_manager`) before the vault-scoped data action check. Sofia holds `crypto_manager` globally, and Key Vault Crypto Officer's bundle includes `Microsoft.KeyVault/vaults/keys/create`, so both gates pass.",
        source:
          "VAULT_USER_ACCESS_JOURNEYS_v3.md § Correction 8; model/azure_roles.go (RoleKeyVaultCryptoOfficer bundle)",
      },
      {
        id: "C2",
        title: "Create an ECDSA key on P-384",
        surface: "cli",
        gate: "none",
        command: `rocketvault keys create --name payments-ec --type ECDSA --curve P-384 \\
  --tags prod --vault prod`,
        expected: "The key is created.",
        assert: "P-384 accepted",
      },
      {
        id: "C3",
        title: "P-256K works but is stored as ES256K, not ECDSA",
        surface: "cli",
        gate: "none",
        command: `rocketvault keys create --name secp-key --type ECDSA --curve P-256K --vault prod
rocketvault keys get <secp-key-id> --vault prod --output json | jq .Type`,
        expected: '"ES256K"',
        assert: "Type reads ES256K, not ECDSA",
        flag: "trap",
        notes:
          '`--type ES256K` is rejected — reach a secp256k1 key only via `--type ECDSA --curve P-256K`. The key is then stored with type `ES256K`, so tooling asserting `type == "ECDSA"` misses these keys silently.',
      },
      {
        id: "C4",
        title: "3072-bit keys are accepted",
        surface: "cli",
        gate: "validation",
        command: `rocketvault keys create --name rsa-3072 --type RSA --bits 3072 --vault prod`,
        expected: "The key is created.",
        assert: "3072 accepted even though --help says 2048 or 4096",
        flag: "gap",
      },
      {
        id: "C5",
        title: "An invalid key size fails only after a full round trip",
        surface: "cli",
        gate: "validation",
        command: `rocketvault keys create --name rsa-bad --type RSA --bits 1234 --vault prod`,
        expected:
          "Rejected — but only after authenticating, never at parse time.",
        assert: "Rejected late, not at flag-parse time",
        flag: "gap",
        why: "cobra's `Int` flag type accepts any integer, so `--bits 1234` parses without complaint. The size check happens only inside `KeyService.CreateRSAKey` (`req.Bits != 2048 && req.Bits != 3072 && req.Bits != 4096`), which runs after the CLI's `admin`/`crypto_manager` check and the vault data-action check have both already passed.",
        source:
          "cmd/keys/create.go (flag registration and auth ordering); internal/services/keys/key_service.go:276",
      },
      {
        id: "C6",
        title: "Sign and verify a payload",
        surface: "cli",
        gate: "none",
        command: `DATA=$(echo -n '{"sub":"txn-1"}' | base64)

SIG=$(rocketvault keys sign --key-id <key-id> --data "$DATA" \\
        --algorithm RS256 --vault prod)

rocketvault keys verify --key-id <key-id> --data "$DATA" \\
  --signature "$SIG" --algorithm RS256 --vault prod`,
        expected: "valid: true",
        assert: "Round trip verifies",
      },
      {
        id: "C7",
        title: "A tampered payload fails verification",
        surface: "cli",
        gate: "none",
        command: `TAMPERED=$(echo -n '{"sub":"attacker"}' | base64)
rocketvault keys verify --key-id <key-id> --data "$TAMPERED" \\
  --signature "$SIG" --algorithm RS256 --vault prod`,
        expected: "valid: false",
        assert: "valid: false — a clean answer, not an error",
      },
      {
        id: "C8",
        title: "Update mutable attributes without touching key material",
        surface: "cli",
        gate: "none",
        command: `rocketvault keys update <key-id> --tags prod,jwt,q3-review --vault prod`,
        expected: "Key <key-id> updated successfully at 2026-08-25T...",
        assert: "Tags change; key material does not",
      },
      {
        id: "C9",
        title: "Revoking breaks crypto but leaves metadata readable",
        surface: "cli",
        gate: "none",
        command: `rocketvault keys update <key-id> --revoked --vault prod
rocketvault keys sign --key-id <key-id> --data "$DATA" --algorithm RS256 --vault prod`,
        expected: "Error: ... key is revoked",
        assert: "Sign fails; keys get still returns the record",
        after:
          "The key stays revoked until C10's `--revoked=false` explicitly restores it. Every sign against it fails in the meantime, including a later case run out of order that assumes the key is usable.",
        source:
          "VAULT_USER_ACCESS_JOURNEYS_v3.md § Journey C (revoke / un-revoke sequence)",
      },
      {
        id: "C10",
        title: "Un-revoke with an explicit false",
        surface: "cli",
        gate: "none",
        command: `rocketvault keys update <key-id> --revoked=false --vault prod`,
        expected: "The key signs again.",
        assert: "--revoked=false restores the key",
        notes:
          "The `=false` form is required. A bare `--revoked` sets it true.",
      },
      {
        id: "C11",
        title: "keys update requires at least one field",
        surface: "cli",
        gate: "validation",
        command: `rocketvault keys update <key-id> --vault prod`,
        expected:
          "Error: at least one update field (name, revoked, tags, purge-protection) must be provided",
        assert: "Empty update rejected rather than treated as a no-op",
      },
      {
        id: "C12",
        title: "Old key versions still verify after a rotation",
        surface: "cli",
        gate: "none",
        command: `rocketvault keys rotate <key-id> --vault prod

rocketvault keys verify --key-id <key-id> --data "$DATA" \\
  --signature "$SIG" --algorithm RS256 --version 1 --vault prod`,
        expected:
          "valid: true — the signature made before rotation still verifies",
        assert: "--version 1 reaches the pre-rotation material",
        notes:
          "`--version 0` or an omitted `--version` means the current version. This is the assertion that proves rotation is additive, not destructive.",
        why: "The first rotation archives the pre-rotation material as version 1 before writing the new material as the next version — it is not overwritten in place. `--version 1` still resolves to that archived row after rotation, which is what lets the pre-rotation signature keep verifying.",
        related: [{ id: "C6", rel: "depends" }],
        source: "internal/services/keys/key_service.go:1112-1131",
      },
      {
        id: "C13",
        title: "A key with no rotation policy reports, rather than errors",
        surface: "cli",
        gate: "none",
        command: `rocketvault keys rotation-policy get <key-id> --vault prod`,
        expected: "No rotation policy set for key <key-id>",
        assert: "Exit is clean; the message is informational",
        why: '`keys rotation-policy get` treats `sql.ErrNoRows` from `GetKeyRotationPolicy` as the ordinary "nothing configured" case: it logs success, prints the informational line, and returns `nil` instead of surfacing an error.',
        source: "cmd/keys/rotation_policy.go:101-107",
      },
      {
        id: "C14",
        title: "rotation-policy set is a full replace, not a partial update",
        surface: "cli",
        gate: "validation",
        command: `rocketvault keys rotation-policy set <key-id> --vault prod`,
        expected: `Error: --rotate-after-days and --enabled are required: this replaces the
whole policy, so every field must be supplied`,
        assert: "Missing flags are a validation error, not “leave unchanged”",
        flag: "trap",
        notes:
          "Contrast with `vaults update` (A5), which *is* a partial update. The two are inconsistent by design — mirror the HTTP `PUT` semantics here.",
        why: 'The command checks `cmd.Flags().Changed("rotate-after-days")` and `Changed("enabled")` directly, rather than reading their zero-value defaults — an omitted flag would otherwise be indistinguishable from an explicitly-set default — so both are required on every call to keep the full-replace contract honest.',
        source: "cmd/keys/rotation_policy.go:185-187",
      },
      {
        id: "C15",
        title: "Azure parity: rotate-after-days must be at least 7",
        surface: "cli",
        gate: "validation",
        command: `rocketvault keys rotation-policy set <key-id> --rotate-after-days 3 --enabled --vault prod`,
        expected: `Error: invalid rotation policy: RotateAfterDays: must be at least 7 when
the policy is enabled.`,
        assert: "Rejected below 7 days when enabled",
        why: "The 7-day minimum is enforced with `validation.By` and a custom function, not ozzo-validation's built-in `validation.Min` — `Min`/`Max` skip validation entirely on a field's zero value, which would let `RotateAfterDays: 0` (continuous re-rotation) through silently whenever the policy is enabled.",
        source:
          "internal/validation/key_validation.go (ValidateKeyRotationPolicy)",
      },
      {
        id: "C16",
        title: "Set a full rotation policy",
        surface: "cli",
        gate: "global-role",
        command: `rocketvault keys rotation-policy set <key-id> --vault prod \\
  --rotate-after-days 90 --notify-before-expiry-days 14 --expiry-days 365 --enabled`,
        expected:
          "Rotation policy set for key <key-id>: next rotation at 2026-11-23T...",
        assert: "Policy stored; next rotation date computed",
      },
      {
        id: "C17",
        title: "The HTTP PUT has the same full-replace contract",
        surface: "http",
        gate: "vault-role",
        command: `curl -s -X PUT $BASE/vaults/prod/keys/<key-id>/rotationpolicy \\
  -H "Authorization: Bearer $SOFIA_TOKEN" -H "Content-Type: application/json" \\
  -d '{"rotate_after_days":90,"notify_before_expiry_days":14,
       "expiry_days":365,"enabled":true}' | jq .`,
        expected: "The stored policy, echoed back.",
        assert: "All four fields required; an omitted one zeroes itself",
        flag: "trap",
        notes:
          "An omitted field silently zeroes rather than leaving the stored value alone. Same trap as C14, different door.",
        why: "`UpsertKeyRotationPolicyRequest`'s fields are plain `int`/`bool`, not pointers, so decoding a JSON body with a field left out just leaves that field at its Go zero value rather than signalling \"not provided.\" The HTTP `PUT` and the CLI's `rotation-policy set` both call the same `KeyService.UpsertKeyRotationPolicy` with that struct, so both write all four fields unconditionally.",
        source: "model/key_rotation_policy.go:40-45",
      },
      {
        id: "C18",
        title: "notify_before_expiry_days is stored and never read",
        surface: "cli",
        gate: "none",
        command: `rocketvault keys rotation-policy get <key-id> --vault prod --output json`,
        expected:
          "The field echoes back the 14 set in C16. Nothing ever sends a notification.",
        assert: "Value round-trips; no notification is ever delivered",
        flag: "gap",
        notes:
          "Do not build an operational process that depends on RocketVault warning you before expiry.",
        why: "There is no outbound HTTP anywhere in the vault, secret or key service packages, so a configured `notify_before_expiry_days` is stored and read back correctly but nothing ever sends a notification from it — the value is inert.",
        verify: {
          look: "The CLI's JSON output uses the command's table headers verbatim as keys, so the field reads back as `Notify-Before-Expiry-Days` (with hyphens), not `notify_before_expiry_days` — and its value is `14`, the number set in C16.",
        },
        source:
          'VAULT_USER_ACCESS_JOURNEYS_v3.md § Journey C ("What actually executes on schedule"); cmd/keys/rotation_policy.go (headers `["Enabled", "Rotate-After-Days", "Notify-Before-Expiry-Days", "Expiry-Days", "Last-Rotated", "Next-Rotation"]`)',
      },
      {
        id: "C19",
        title: "Deleting the policy stops the scheduler, not the key",
        surface: "cli",
        gate: "global-role",
        command: `rocketvault keys rotation-policy delete <key-id> --vault prod`,
        expected: "Rotation policy for key <key-id> deleted successfully",
        assert: "Policy gone; manual keys rotate still works",
        related: [{ id: "C16", rel: "depends" }],
      },
      {
        id: "C20",
        title: "Deleting a policy twice errors the second time",
        surface: "cli",
        gate: "none",
        command: `rocketvault keys rotation-policy delete <key-id> --vault prod`,
        expected: "Error: no rotation policy exists for key <key-id>",
        assert: "Not idempotent — contrast with vault-webhook delete (U8)",
        related: [{ id: "C19", rel: "depends" }],
      },
      {
        id: "C21",
        title: "Key import does not exist",
        surface: "cli",
        gate: "none",
        command: `rocketvault keys import ...`,
        expected: 'Error: unknown command "import" for "rocketvault keys"',
        assert: "Unknown command",
        flag: "gap",
        why: "`ActionKeysImport` is defined and included in the Crypto Officer role bundle, but `cmd/keys.go` registers no `import` subcommand, and no HTTP route maps to that action either — the permission was modeled ahead of the capability existing.",
        source:
          "VAULT_USER_ACCESS_JOURNEYS_v3.md § Correction 9; model/azure_roles.go:189-192 (RoleKeyVaultCryptoOfficer bundle includes ActionKeysImport)",
      },
      {
        id: "C22",
        title: "A duplicate key name leaks a raw driver error",
        surface: "cli",
        gate: "none",
        command: `rocketvault keys create --name payments-signing --type RSA --bits 4096 --vault prod`,
        expected:
          "UNIQUE constraint failed: keys.vault_id, keys.name  (on SQLite)",
        assert: "Rejected only after RSA generation, with an unwrapped error",
        flag: "gap",
        notes:
          "If you script this, match on `UNIQUE constraint failed` rather than a friendly message.",
        why: "The insert wraps SQLite's constraint violation in `ErrNameTaken` (`a resource with this name already exists in this vault`), but the wrap uses `%w` twice and does not discard the underlying driver error, so the raw `UNIQUE constraint failed` text still appears in the final message alongside the friendlier one. The check only runs at insert time, which is after `CreateRSAKey` has already generated the RSA key material.",
        verify: {
          look: 'The full CLI error is longer than the fragment shown in `expected` — it reads `failed to create key: key "payments-signing": a resource with this name already exists in this vault: UNIQUE constraint failed: keys.vault_id, keys.name`. Match on the `UNIQUE constraint failed` substring, not the whole line.',
        },
        source:
          "internal/repositories/key_repository.go:380-395; internal/repositories/name_taken_errors.go:5-9; internal/repositories/key_repository.go:389-395",
      },
      {
        id: "C23",
        title: "The CLI barely validates key names; HTTP does",
        surface: "both",
        gate: "validation",
        command: `rocketvault keys create --name '9-starts-with-a-digit' --type RSA --bits 2048 --vault prod`,
        expected:
          "The CLI accepts it. HTTP enforces ^[a-zA-Z][a-zA-Z0-9-]{0,126}$ and would reject it.",
        assert: "A CLI-created key can violate a constraint HTTP enforces",
        flag: "divergence",
        why: '`ValidateKeyCreate` — which includes the `KeyNameRule` regex — is only called from the HTTP handler in `api/keys.go`. `cmd/keys/create.go`\'s `RunE` checks just `name == "" || keyType == ""` before calling `KeyService.CreateRSAKey`/`CreateECDSAKey` directly, so the same regex the HTTP path enforces never runs on the CLI path.',
        source:
          "api/keys.go:356 (ValidateKeyCreate call); cmd/keys/create.go (name/type check only); internal/validation/key_validation.go:26-40",
      },
    ],
  },
  {
    key: "D",
    title: "CI/CD service account, sign-only",
    actor: "ci-payments-svc — REST only",
    premise:
      "A service account's grant runs the same `HasDataAction` codepath as a human's, with the same per-vault scoping. Service accounts never touch the CLI session cache.",
    cases: [
      {
        id: "D1",
        title: "Grant a role to a service account",
        surface: "cli",
        gate: "management",
        command: `rocketvault vault-access grant ci-payments-svc --role "Key Vault Crypto User" \\
  --principal-type service_account --vault prod`,
        expected: "The assignment is created.",
        assert: "--principal-type service_account accepted",
        notes:
          "Omitting `--principal-type` treats the name as a user, which will not match the service account.",
      },
      {
        id: "D2",
        title: "The assignment appears in the vault listing",
        surface: "cli",
        gate: "management",
        command: `rocketvault vault-access list --vault prod`,
        expected: `ASSIGNMENT-ID                          ROLE                 PRINCIPAL-ID
<assignment-id>                        Key Vault Crypto User <ci-payments-svc-client-id>`,
        assert: "Service account listed alongside human principals",
        flag: "trap",
        notes:
          "Match the service account by its client id, not by name — the name never appears in this output.",
        why: "`vault-access list` writes a fixed `ASSIGNMENT-ID`/`ROLE`/`PRINCIPAL-ID` table with `fmt.Fprintf` and never reads `--output`, so there is no JSON form of this command. The principal column is the raw `PrincipalID` UUID; no username lookup happens on this path. A `principal_username` field does exist, but only on the HTTP API's `model.RoleAssignmentResponse`, not here.",
        verify: {
          look: "Three whitespace-separated columns and no JSON — passing `--output json` changes nothing. The third column is the service account's client id as a UUID, not the string `ci-payments-svc`.",
        },
        source:
          "cmd/vault-access/list.go:25,28,76,78; api/role_assignments.go:35 (principal_username is HTTP-only)",
      },
      {
        id: "D3",
        title: "Obtain a token by client-credentials grant",
        surface: "http",
        gate: "none",
        command: `SVC_TOKEN=$(curl -s -X POST $BASE/oauth2/token \\
  -H "Content-Type: application/json" \\
  -d '{"grant_type":"client_credentials",
       "client_id":"ci-payments-svc","client_secret":"'"$VAULT_CLIENT_SECRET"'"}' \\
  | jq -r .access_token)`,
        expected: "A JWT.",
        assert: "Token issued with no TOTP and no session file",
      },
      {
        id: "D4",
        title: "Crypto User can sign",
        surface: "http",
        gate: "vault-role",
        command: `curl -s -X POST $BASE/vaults/prod/keys/<key-id>/sign \\
  -H "Authorization: Bearer $SVC_TOKEN" -H "Content-Type: application/json" \\
  -d '{"value":"'"$DATA"'","algorithm":"RS256"}' | jq -r .value`,
        expected: "A signature.",
        assert: "200 with a signature body",
      },
      {
        id: "D5",
        title: "Crypto User cannot create a key",
        surface: "http",
        gate: "vault-role",
        command: `curl -s -o /dev/null -w '%{http_code}\\n' -X POST $BASE/vaults/prod/keys \\
  -H "Authorization: Bearer $SVC_TOKEN" -H "Content-Type: application/json" \\
  -d '{"name":"scratch","type":"RSA","bits":2048}'`,
        expected: "403",
        assert: "403 — Crypto User has no keys/create",
        why: "Key Vault Crypto User's bundle covers using key material — read, update, encrypt, decrypt, wrap, unwrap, sign, verify, backup — but not `Microsoft.KeyVault/vaults/keys/create`, which belongs only to Crypto Officer and Administrator.",
        related: [{ id: "D4", rel: "contrasts" }],
        source: "model/azure_roles.go (RoleKeyVaultCryptoUser bundle)",
      },
      {
        id: "D6",
        title: "Crypto User does include update and backup",
        surface: "http",
        gate: "vault-role",
        command: `curl -s -o /dev/null -w '%{http_code}\\n' -X POST $BASE/vaults/prod/keys/<key-id>/backup \\
  -H "Authorization: Bearer $SVC_TOKEN"`,
        expected: "200 — a master-key-encrypted blob, not plaintext PEM.",
        assert: "Backup permitted under Crypto User",
        flag: "trap",
        notes:
          "Threat-model precision: the blob is ciphertext, but it is still key material. “Can use a key, can't manage it” is not an accurate description of this role.",
        why: "Crypto User's bundle includes `update` and `backup` alongside the use-the-key actions — it is not limited to using a key while never touching its lifecycle. A backup blob is the master-key-encrypted key value, so this role can export key material off the vault even though it cannot create, delete, rotate or import a key.",
        related: [{ id: "D5", rel: "contrasts" }],
        source:
          "model/azure_roles.go (RoleKeyVaultCryptoUser bundle); VAULT_USER_ACCESS_JOURNEYS_v3.md § Journey D — Threat-model precision",
      },
    ],
  },
  {
    key: "E",
    title: "The narrowest possible crypto grant",
    actor: "checkout-api-svc — Crypto Service Encryption User",
    premise:
      "Wrap and unwrap, and nothing else. The failure that matters is what happens when a buggy client calls `encrypt` instead of `wrap`.",
    cases: [
      {
        id: "E1",
        title: "Grant the encryption-user role",
        surface: "cli",
        gate: "management",
        command: `rocketvault vault-access grant checkout-api-svc \\
  --role "Key Vault Crypto Service Encryption User" \\
  --principal-type service_account --vault prod`,
        expected: "The assignment is created.",
        assert: "Role name accepted verbatim",
      },
      {
        id: "E2",
        title: "Wrap/unwrap round-trips over the CLI",
        surface: "cli",
        gate: "none",
        precondition: "Run as an operator, to demonstrate the shape.",
        command: `MATERIAL=$(openssl rand -base64 32)

WRAPPED=$(rocketvault keys wrap --key-id <rsa-key-id> \\
            --key-material "$MATERIAL" --vault prod)

rocketvault keys unwrap --key-id <rsa-key-id> \\
  --wrapped-key "$WRAPPED" --vault prod`,
        expected: "The original $MATERIAL, printed back.",
        assert: "Unwrap returns the input byte-for-byte",
      },
      {
        id: "E3",
        title: "The CLI always requests RSA-OAEP",
        surface: "cli",
        gate: "validation",
        command: `rocketvault keys wrap --key-id <rsa-key-id> --key-material "$MATERIAL" \\
  --algorithm AES-KW --vault prod`,
        expected: "Unknown flag — there is no --algorithm on wrap or unwrap.",
        assert: "No --algorithm flag exists",
        flag: "gap",
        notes: "AES key wrapping is REST-only.",
        why: '`keys wrap`/`keys unwrap` hardcode `Algorithm: "RSA-OAEP"` in the request they build, and neither command registers an `--algorithm` flag to override it.',
        source: "cmd/keys/wrap.go:125,149-154; cmd/keys/unwrap.go:125,149-154",
      },
      {
        id: "E4",
        title: "The service can wrap over HTTP",
        surface: "http",
        gate: "vault-role",
        command: `curl -s -X POST $BASE/vaults/prod/keys/<key-id>/wrap \\
  -H "Authorization: Bearer $CHECKOUT_TOKEN" -H "Content-Type: application/json" \\
  -d '{"plaintext_key":"'"$MATERIAL"'","algorithm":"RSA-OAEP"}' | jq -r .wrapped_key`,
        expected: "The wrapped key.",
        assert: "200 with wrapped_key",
      },
      {
        id: "E5",
        title: "Calling encrypt instead of wrap fails closed",
        surface: "http",
        gate: "vault-role",
        command: `curl -s -o /dev/null -w '%{http_code}\\n' -X POST $BASE/vaults/prod/keys/<key-id>/encrypt \\
  -H "Authorization: Bearer $CHECKOUT_TOKEN" -H "Content-Type: application/json" \\
  -d '{"algorithm":"RSA-OAEP-256","value":"'"$DATA"'"}'`,
        expected: "403",
        assert: "403 — this role has no keys/encrypt",
        notes:
          "The point of the case: a bug that hits the wrong endpoint is refused rather than silently doing different crypto.",
        why: "Key Vault Crypto Service Encryption User's bundle is `keys/read`, `keys/wrap` and `keys/unwrap` only — it holds no `Microsoft.KeyVault/vaults/keys/encrypt/action`, so `HasDataAction` denies the `/encrypt` route regardless of which key is targeted.",
        related: [{ id: "E4", rel: "contrasts" }],
        source:
          "model/azure_roles.go (RoleKeyVaultCryptoServiceEncryptionUser bundle)",
      },
      {
        id: "E6",
        title: "CBC modes are rejected on wrap, allowed on encrypt",
        surface: "http",
        gate: "validation",
        precondition: "HSM-backed keys only.",
        command: `# wrap with A256CBC -- rejected
# encrypt/decrypt with A256CBC -- accepted, and round-trips the IV`,
        expected:
          "Wrap refuses A128CBC/A192CBC/A256CBC; encrypt and decrypt accept them.",
        assert: "The wrap contract carries no IV channel",
        notes:
          "On HSM-backed keys wrap/unwrap is limited to AES-KW and the RSA-OAEP variants. This is a contract limit, not an authorization one.",
        why: "The wrap/unwrap contract carries no IV channel to round-trip, so CBC's required IV has nowhere to travel. Encrypt/decrypt do carry one and can support CBC. This is a limit on the operation's contract shape, not a role or authorization check.",
        related: [{ id: "E4", rel: "contrasts" }],
        source:
          "VAULT_USER_ACCESS_JOURNEYS_v3.md § Journey E (closing paragraph)",
      },
    ],
  },
  {
    key: "F",
    title: "Crypto User hits the rotation-policy wall",
    actor: "cryptouser — Key Vault Crypto User and nothing else",
    premise:
      "The whole journey exists for one contrast: the same route returns 403 for this principal and 404 for an admin. A test asserting only “non-200” cannot tell a denial from an empty resource.",
    cases: [
      {
        id: "F1",
        title: "Grant Crypto User and nothing else",
        surface: "cli",
        gate: "management",
        command: `rocketvault vault-access grant cryptouser --role "Key Vault Crypto User" --vault prod`,
        expected: "One assignment.",
        assert: "Exactly one role held in prod",
      },
      {
        id: "F2",
        title: "Crypto User can encrypt",
        surface: "http",
        gate: "vault-role",
        command: `curl -s -X POST $BASE/vaults/prod/keys/<key-id>/encrypt \\
  -H "Authorization: Bearer $CU_TOKEN" -H "Content-Type: application/json" \\
  -d '{"algorithm":"RSA-OAEP-256","value":"'"$DATA"'"}'`,
        expected: "200",
        assert: "200",
        related: [{ id: "F4", rel: "contrasts" }],
      },
      {
        id: "F3",
        title: "Crypto User gained update on 2026-08-18",
        surface: "http",
        gate: "vault-role",
        command: `curl -s -X PUT $BASE/vaults/prod/keys/<key-id> \\
  -H "Authorization: Bearer $CU_TOKEN" -H "Content-Type: application/json" \\
  -d '{"tags":["updated-by-cryptouser"]}'`,
        expected: "200",
        assert: "200 — update is in the bundle",
        why: "Crypto User's bundle includes `Microsoft.KeyVault/vaults/keys/update` alongside the use-the-key actions, which is what this `PUT` succeeds against.",
        source: "model/azure_roles.go (RoleKeyVaultCryptoUser bundle)",
      },
      {
        id: "F4",
        title: "All three rotation-policy methods are denied",
        surface: "http",
        gate: "vault-role",
        command: `for M in GET PUT DELETE; do
  curl -s -o /dev/null -w "$M %{http_code}\\n" -X $M \\
    $BASE/vaults/prod/keys/<key-id>/rotationpolicy \\
    -H "Authorization: Bearer $CU_TOKEN"
done`,
        expected: `GET 403
PUT 403
DELETE 403`,
        assert: "403 on all three verbs",
        why: "Crypto User's bundle has no `rotationpolicy/read` or `rotationpolicy/write` entry at all — those two actions exist only in the Crypto Officer and Administrator bundles — so `HasDataAction` denies all three HTTP verbs on this route before any handler runs.",
        related: [{ id: "F5", rel: "diverges" }],
        source:
          "model/azure_roles.go (RoleKeyVaultCryptoUser bundle, contrasted with RoleKeyVaultCryptoOfficer / RoleKeyVaultAdministrator)",
      },
      {
        id: "F5",
        title: "The contrast that proves these are real denials",
        surface: "http",
        gate: "none",
        command: `curl -s -o /dev/null -w '%{http_code}\\n' \\
  $BASE/vaults/prod/keys/<key-id>/rotationpolicy \\
  -H "Authorization: Bearer $ADMIN_TOKEN"`,
        expected: "404 rotation policy not found — a genuine “nothing set yet”",
        assert: "404, not 403 — same route, different principal",
        flag: "divergence",
        notes:
          "Commit `cdd591c` added the rotation-policy actions to Crypto Officer and Administrator only, stating *“not Crypto User, matching Azure.”* The exclusion is deliberate.",
        why: "Priya already holds Key Vault Administrator in `prod` from her Journey A self-grant, and that bundle includes both rotation-policy actions, so her `GET` passes the vault-role check and reaches the handler — which reports 404 because this key has no policy set. cryptouser's role grants neither action, so their request is denied before it ever reaches the handler; that is F4's 403 on the same route.",
        related: [
          { id: "A9", rel: "depends" },
          { id: "F4", rel: "diverges" },
        ],
        source:
          "VAULT_USER_ACCESS_JOURNEYS_v3.md § Journey A (self-grant Key Vault Administrator); model/azure_roles.go (RoleKeyVaultAdministrator bundle)",
      },
    ],
  },
]
