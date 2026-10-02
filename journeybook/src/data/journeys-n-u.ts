import type { Suite } from "./types"

export const journeysNU: Suite[] = [
  {
    key: "N",
    title: "Multi-vault isolation verification",
    actor: "alice and bob — one vault each",
    premise:
      "Cross-vault access must be a 403 deny-by-default, never a 404 and never a partial leak. The cache check at the end is a security assertion, not a performance one.",
    cases: [
      {
        id: "N1",
        title: "Two users, one vault each",
        surface: "cli",
        gate: "management",
        command: `rocketvault vault-access grant alice --role "Key Vault Secrets Officer" --vault vault-a
rocketvault vault-access grant bob   --role "Key Vault Secrets Officer" --vault vault-b`,
        expected: "Two assignments in two vaults.",
        assert: "Neither principal holds anything in the other's vault",
        why: "Every role assignment is a row scoped to one `vault_id`, looked up by the exact pair `(principal_id, vault_id)`. Granting alice a role in vault-a inserts a row naming vault-a only, so a later lookup for alice against vault-b returns nothing, no matter what she holds elsewhere.",
        related: [
          { id: "N2", rel: "depends" },
          { id: "N5", rel: "depends" },
        ],
        source:
          "internal/services/authorization/role_assignment_service.go:213-229 (HasDataAction -> ListByPrincipalInVault); internal/db/db.go:709-721 (role_assignments schema)",
      },
      {
        id: "N2",
        title: "Alice cannot reach vault-b's secret by exact UUID",
        surface: "cli",
        gate: "vault-role",
        command: `rocketvault secrets get <vault-b-secret-id> --vault vault-b`,
        expected: "Error: forbidden: no role grants ... in this vault",
        assert: "Denied even with the exact id in hand",
        why: "The CLI's `authorization.RequireDataAction` calls `HasDataAction(alice, vault-b, action)`, which lists role assignments filtered by `(principal_id, vault_id)` for vault-b specifically. That query has no admin short-circuit and returns zero rows for alice, so the deny is a plain role-assignment miss — the secret's exact UUID never enters this check at all.",
        source: "internal/services/authorization/data_action_authz.go:29-38",
      },
      {
        id: "N3",
        title: "403, not 404, and not a silent success",
        surface: "http",
        gate: "vault-role",
        command: `curl -s -o /dev/null -w '%{http_code}\\n' $BASE/vaults/vault-b/secrets/<id> \\
  -H "Authorization: Bearer $ALICE_TOKEN"`,
        expected: "403 — not a silent success, not a partial leak",
        assert: "Exactly 403",
        notes:
          "v1 of this document claimed 404. It is 403 deny-by-default. Retract any test asserting 404.",
        why: "Over HTTP the same `HasDataAction(principal, vault, action)` lookup runs from inside `PolicyMiddleware`'s deny-by-default step, not from the CLI's `RequireDataAction` — a different code path reaching the identical role-assignment miss as N2, worded as `Forbidden: no role assignment grants this operation in this vault` in the response body (discarded here since the command captures only the status code).",
        source: "internal/middleware/middleware.go:562-575",
      },
      {
        id: "N4",
        title: "The default vault cannot be deleted",
        surface: "cli",
        gate: "management",
        command: `rocketvault vaults delete default`,
        expected: "Error: the default vault cannot be deleted",
        assert: "Refused — otherwise `default` behaves like any named vault",
        why: "`DeleteVault` special-cases the literal name `default` before it runs the normal soft-delete path, and refuses outright rather than allowing a soft-delete that would later need reversing.",
        source: "internal/services/vaults/vault_service.go:628-629",
      },
      {
        id: "N5",
        title:
          "A stale vault cache must not produce a wrong authorization answer",
        surface: "http",
        gate: "vault-role",
        precondition: "cache.vaults.enabled: true, inside a live TTL window.",
        command: `curl -s -X PATCH $BASE/vaults/vault-a \\
  -H "Authorization: Bearer $ADMIN_TOKEN" -H "Content-Type: application/json" \\
  -d '{"enabled":false}'

# Immediately resolve the same vault by name through a different path:
curl -s -o /dev/null -w '%{http_code}\\n' $BASE/vaults/vault-a/secrets \\
  -H "Authorization: Bearer $ALICE_TOKEN"`,
        expected:
          "The answer must reflect the vault being disabled, not a stale cached record.",
        assert: "No incorrect authorization decision from a cached vault",
        flag: "trap",
        notes:
          "This is a security check that happens to look like a cache check.",
        why: "The 403 here has to come from `VaultResolutionMiddleware`'s check on the resolved vault's `Enabled` field, a check on vault state, not on alice's role assignments — she holds a valid `Key Vault Secrets Officer` grant in vault-a from N1, so a role-based check alone would let her through. `VaultService.UpdateVault` invalidates the `vaultcache` entry for the vault synchronously, in the same call that persists `enabled: false`, before it returns; when `cache.rocket_mem` is active, invalidation evicts both the in-process and Rocket-mem tiers together. The very next resolution is therefore a cache miss that reads the fresh, disabled row.",
        verify: {
          look: "The second `curl` must return `403` even though alice's own role grant in vault-a would otherwise let it through — the deny has to come from `vault.Enabled` being false, not from a role gap. A `200` here means the pre-disable vault record served from a stale cache entry, which would be a genuine bug in this build, not a passed check.",
        },
        source:
          "internal/services/vaults/vault_service.go:591-624; internal/middleware/middleware.go:634-644; internal/cachekit/tiered_cache.go:91; internal/services/vaults/vault_service.go:614-619",
      },
    ],
  },
  {
    key: "O",
    title: "Migrating a secret set to a new vault",
    actor: "Marcus — secrets_manager",
    premise:
      "Export, import, and the three ways the passphrase can be wrong. Two named traps: `generate-password` is not the HTTP generate route, and `--format` describes the payload inside the envelope, not the file on disk.",
    cases: [
      {
        id: "O1",
        title: "Provision the new vault and mirror the role",
        surface: "cli",
        gate: "management",
        command: `rocketvault vaults create payments

rocketvault vault-access grant priya  --role "Key Vault Administrator" --vault payments
rocketvault vault-access grant marcus --role "Key Vault Secrets Officer" --vault payments`,
        expected: "The vault exists and both principals hold a role in it.",
        assert: "Priya must self-grant here too (see A7)",
        why: "`CreateVault`, the path an admin's `vaults create` runs, inserts the vault row and returns — it never runs the creator-grant transaction that `CreateVaultProvisioned` runs for a provisioning-grant or global-policy holder. Priya gets no role inside `payments` just for creating it, the same fact A7 established for `prod`, so she must self-grant here too.",
        related: [{ id: "A7", rel: "depends" }],
        source: "internal/services/vaults/vault_service.go:323-340,365-372",
      },
      {
        id: "O2",
        title: "generate-password runs entirely locally",
        surface: "local",
        gate: "none",
        command: `GENERATED_PW=$(rocketvault secrets generate-password --length 24 --special=true \\
  | awk '{print $NF}')`,
        expected: "Generated password: <24 random chars>",
        assert: "No login, no vault, nothing stored",
      },
      {
        id: "O3",
        title: "generate-password is NOT the HTTP generate route",
        surface: "both",
        gate: "none",
        command: `# CLI:  prints a string, never touches a vault
# HTTP: POST /vaults/{name}/secrets/generate takes a name and creates
#       the secret in one step, storing the value`,
        expected:
          "Two different operations that share a name. Neither surface has the other's behaviour.",
        assert: "No CLI command does what the HTTP route does, and vice versa",
        flag: "divergence",
      },
      {
        id: "O4",
        title: "Create a secret from the generated value",
        surface: "cli",
        gate: "global-role",
        command: `rocketvault secrets create payments-db-pass "$GENERATED_PW" --tags prod,db --vault payments`,
        expected: "The secret is created.",
        assert: "Succeeds — Marcus holds secrets_manager globally",
      },
      {
        id: "O5",
        title: "Export is encrypted by default",
        surface: "cli",
        gate: "global-role",
        command: `export ROCKETVAULT_EXPORT_PASSPHRASE='correct-horse-battery-staple'

rocketvault secrets export --file /tmp/payments-legacy.json \\
  --tags payments-legacy --vault dev`,
        expected: `Secrets exported successfully
Format: json
Encryption: passphrase (argon2id + AES-256-GCM)
File: /tmp/payments-legacy.json`,
        assert: "Encryption line reads argon2id + AES-256-GCM",
        why: "`--encrypt` defaults to `true` on `secrets export`, so a call with no explicit `--encrypt=false` seals the file with an argon2id-derived key under AES-256-GCM regardless of `--format`.",
        source: "cmd/secrets/export.go:63-65,284",
      },
      {
        id: "O6",
        title: "Import with no passphrase available names the fix",
        surface: "cli",
        gate: "validation",
        command: `unset ROCKETVAULT_EXPORT_PASSPHRASE

rocketvault secrets import --file /tmp/payments-legacy.json --vault payments`,
        expected: `Error: /tmp/payments-legacy.json is an encrypted export but no passphrase
is available: pass --passphrase-file or set ROCKETVAULT_EXPORT_PASSPHRASE`,
        assert: "The error names both ways to supply it",
        why: "`common.ResolvePassphrase` returns `ErrNoPassphraseAvailable` when neither `--passphrase-file` nor the `ROCKETVAULT_EXPORT_PASSPHRASE`-named env var supplies a value; `secrets import` turns that specific error into the message naming both options, before it ever attempts to open the envelope.",
        source: "cmd/secrets/import.go:139-150",
      },
      {
        id: "O7",
        title: "A wrong passphrase fails differently from a missing one",
        surface: "cli",
        gate: "validation",
        command: `echo 'not-the-real-passphrase' > /tmp/wrong-pass.txt
rocketvault secrets import --file /tmp/payments-legacy.json \\
  --passphrase-file /tmp/wrong-pass.txt --vault payments`,
        expected:
          "Error: failed to decrypt /tmp/payments-legacy.json: wrong passphrase or corrupted file",
        assert: "Distinct message — the file is real, the key does not open it",
        notes:
          "Three distinguishable failures across O6, O7 and a genuinely corrupt file. Assert on the message, not just the exit code.",
        why: "`common.OpenExport` reports `ErrWrongPassphrase` when the derived key fails to open the AES-256-GCM envelope. `secrets import` turns that specific error into a fixed message naming the file — distinct from O6's missing-passphrase error, and distinct from any other `openErr`, which is wrapped with its own underlying error text instead of this fixed wording.",
        source: "cmd/secrets/import.go:153-158",
      },
      {
        id: "O8",
        title: "Correct passphrase, correct target vault",
        surface: "cli",
        gate: "global-role",
        command: `echo 'correct-horse-battery-staple' > /tmp/export-pass.txt
rocketvault secrets import --file /tmp/payments-legacy.json \\
  --passphrase-file /tmp/export-pass.txt --vault payments`,
        expected: `Secrets imported successfully
Imported: 6
Skipped: 0
Failed: 0`,
        assert: "6 imported, 0 skipped, 0 failed",
        after:
          "The real export passphrase is left in plaintext at `/tmp/export-pass.txt` on disk. Delete it once this journey is done — it is not needed again, and leaving it defeats the point of encrypting the export in the first place.",
        related: [{ id: "O7", rel: "contrasts" }],
        source: "VAULT_USER_ACCESS_JOURNEYS_v3.md § Journey O",
      },
      {
        id: "O9",
        title: "--format describes the payload, not the file on disk",
        surface: "cli",
        gate: "validation",
        command: `rocketvault secrets export --file /tmp/x.csv --format csv --vault dev
file /tmp/x.csv                       # reports JSON
rocketvault secrets import --file /tmp/x.csv --format csv --vault payments`,
        expected:
          "A sealed CSV export is a JSON envelope on disk, and is read back with --format csv.",
        assert: "--format csv on import, even though `file` says JSON",
        flag: "trap",
        verify: {
          look: "`file /tmp/x.csv` reporting JSON is the expected, correct result here, not a failure — the sealed envelope on disk is always JSON regardless of `--format`. The only thing to actually check is that `secrets import --format csv` succeeds against that file. A sealed CSV export is read back with `--format csv`, never `--format json`, however the file identifies itself on disk.",
        },
        after:
          "As written, this command has no `--tags` filter, so it exports every secret in `dev` — not just the `payments-legacy` set — and imports all of it into `payments` with `--overwrite` left at its default `false`. Any name that already exists in `payments` from O8 is skipped; every other `dev` secret lands in `payments` as a new copy. Add `--tags payments-legacy` before running this for real, or expect `payments` to end up holding more than the migrated set.",
        source:
          "VAULT_USER_ACCESS_JOURNEYS_v3.md § Journey O; cmd/secrets/export.go:287 (--tags default empty); cmd/secrets/import.go:265 (--overwrite default false)",
      },
      {
        id: "O10",
        title: "HTTP export and import have genuinely different shapes",
        surface: "http",
        gate: "vault-role",
        command: `curl -s -X POST $BASE/vaults/dev/secrets/export \\
  -H "Authorization: Bearer $MARCUS_TOKEN" -H "Content-Type: application/json" \\
  -d '{"format":"json","tags":["payments-legacy"],"include_tags":true,
       "encrypt":true,"passphrase":"correct-horse-battery-staple"}' \\
  -o /tmp/payments-legacy-http.json

curl -s -X POST $BASE/vaults/payments/secrets/import \\
  -H "Authorization: Bearer $MARCUS_TOKEN" \\
  -F "file=@/tmp/payments-legacy-http.json" \\
  -F "format=json" -F "overwrite=false" \\
  -F "passphrase=correct-horse-battery-staple" | jq .`,
        expected: `{"success":true,"message":"Successfully imported 6/6 secrets", ...}`,
        assert: "Export is a JSON body returning bytes; import is multipart",
        why: "`cliclient.ExportSecretsRemote` sends the export request as a JSON body and reads back raw file bytes; `ImportSecretsRemote` builds a `multipart.Writer` body instead. These are two different wire formats for the same feature, not a stylistic difference in how the CLI happens to call them.",
        source: "internal/cliclient/secrets.go:202-255",
      },
      {
        id: "O11",
        title: "Retire the originals one UUID at a time",
        surface: "cli",
        gate: "global-role",
        command: `rocketvault secrets delete <legacy-secret-id> --vault dev`,
        expected: "Soft-deleted. No confirmation prompt.",
        assert: "No --force, no batch form, no prompt",
        flag: "trap",
        notes:
          "Each of the six migrated secrets needs its own invocation. There is no “delete all matching tag”.",
        why: "`secrets delete`'s `RunE` takes `cobra.ExactArgs(1)` and registers no `--force` or batch-selection flag, so each invocation can only soft-delete the one ID it was given.",
        after:
          "The six migrated secrets are soft-deleted in `dev`, not purged — they still occupy rows there. `cmd/secrets` has no recover or purge subcommand, so restoring one before the retention scheduler purges it needs a direct REST call.",
        source: "cmd/secrets/delete.go:64; cmd/secrets/delete.go:44-48",
      },
    ],
  },
  {
    key: "P",
    title: "A user-role principal runs the entire secret-rotation lifecycle",
    actor: "Wren — global role user, Key Vault Secrets Officer in prod",
    premise:
      "`secrets rotation *` is the one command tree with no CLI global-role gate and no HTTP route at all. The same principal is refused `secrets create` and permitted to rotate credentials on demand.",
    cases: [
      {
        id: "P1",
        title: "Grant Secrets Officer to a bare `user`",
        surface: "cli",
        gate: "management",
        command: `rocketvault vault-access grant wren --role "Key Vault Secrets Officer" --vault prod`,
        expected:
          "granted Key Vault Secrets Officer to wren in vault (assignment ...)",
        assert: "Granted",
      },
      {
        id: "P2",
        title: "secrets create is refused before the vault check runs",
        surface: "cli",
        gate: "global-role",
        command: `rocketvault secrets create scratch-secret 'x' --vault prod`,
        expected: "Error: forbidden: requires admin or secrets_manager role",
        assert: "Denied at the global-role gate",
        why: "`secrets create`'s `RunE` checks `HasAnyRole(admin, secrets_manager)` against Wren's global JWT claims first and returns before it ever calls `vaultcli.RequireDataAction`. Her `Key Vault Secrets Officer` grant in `prod` from P1 is never consulted — the global-role gate denies her before the vault-scoped check runs at all.",
        source: "cmd/secrets/create.go:95,105",
      },
      {
        id: "P3",
        title: "secrets rotation create is permitted for the same principal",
        surface: "cli",
        gate: "none",
        command: `rocketvault secrets rotation create --name db-cred-30d --interval 30 \\
  --reminder 7 --auto-rotate --vault prod`,
        expected: `Rotation policy created successfully
Policy ID: <policy-id>
Name: db-cred-30d
Interval: 30 days
Auto-rotate: true`,
        assert: "Succeeds — no global role is checked on this tree",
        flag: "divergence",
        notes:
          "Whether that is an oversight or a scope decision is not documented anywhere as intentional.",
        why: "None of `cmd/rotation.go`'s handlers — `runRotationCreate`, `runRotationAssign`, `runRotationRotate`, and the rest — call `common.HasAnyRole`, the check present in `cmd/secrets/create.go:95` for `secrets create`. Each rotation subcommand goes straight to `vaultcli.RequireDataAction`, so only Wren's vault role assignment is ever checked, and it is enough on its own.",
        related: [{ id: "P2", rel: "contrasts" }],
        source:
          "cmd/rotation.go (runRotationCreate through runRotationStatus, no HasAnyRole call)",
      },
      {
        id: "P4",
        title: "Assign the policy to a real secret",
        surface: "cli",
        gate: "none",
        command: `rocketvault secrets rotation assign --policy-id <policy-id> \\
  --secret-id <secret-id> --vault prod`,
        expected: "Policy assigned to secret successfully.",
        assert: "Assigned",
      },
      {
        id: "P5",
        title: "Re-assigning the same pair leaks a triple-wrapped driver error",
        surface: "cli",
        gate: "none",
        command: `rocketvault secrets rotation assign --policy-id <policy-id> --secret-id <secret-id> --vault prod`,
        expected: `Error: failed to assign policy to secret: failed to assign policy to secret: failed to
assign policy to secret: UNIQUE constraint failed: secret_policies.secret_id, secret_policies.policy_id`,
        assert: "Three layers of the same sentence around one constraint name",
        flag: "gap",
        notes:
          "If you script this, match `UNIQUE constraint failed` rather than a clean message.",
        why: "The repository wraps the raw SQLite `UNIQUE constraint failed: secret_policies.secret_id, secret_policies.policy_id` error as `failed to assign policy to secret: %w`. The service wraps that once more with the identical string, and the CLI's `RunE` wraps it a third time on top of its own `%w` — three layers of the same sentence around one constraint name.",
        source:
          "internal/repositories/rotation_repository.go:218; internal/services/secrets/rotation_service.go:311; cmd/rotation.go:620",
      },
      {
        id: "P6",
        title: "List the rotation policies",
        surface: "cli",
        gate: "none",
        command: `rocketvault secrets rotation list --vault prod`,
        expected: `ID           NAME         INTERVAL  AUTO-ROTATE  ENABLED  CREATED
<policy-id>  db-cred-30d  30 days   true         true     2026-08-25

Found 1 rotation policies`,
        assert: "One policy, auto-rotate true",
      },
      {
        id: "P7",
        title: "Check what is due rather than waiting to find out",
        surface: "cli",
        gate: "none",
        command: `rocketvault secrets rotation status --vault prod`,
        expected: `Rotation Status
Secrets due for rotation:
  - Secret <secret-id-abbrev>... (next: 2026-09-24)

Active rotation policies:
  - db-cred-30d: every 30 days (auto-rotate enabled)`,
        assert: "Due secrets and active policies both listed",
        why: "The secret rotation scheduler starts only inside `App.StartServer`, gated by whether scheduling is enabled, on the interval passed to `SchedulerService.Start` — there is no code path that fires an automatic rotation outside a live `serve` process.",
        verify: {
          look: "The `next:` date is 30 days after whenever P3 actually ran in this test pass, not the literal `2026-09-24` shown here — check the offset from your own run, not the calendar date.",
        },
        source:
          "app/app.go:121-134; VAULT_USER_ACCESS_JOURNEYS_v3.md § Journey P",
      },
      {
        id: "P8",
        title: "Manual rotation needs a value source",
        surface: "cli",
        gate: "validation",
        command: `rocketvault secrets rotation rotate --secret-id <secret-id> --policy-id <policy-id> --vault prod`,
        expected:
          "Error: no new value: pass --value <value> to set one, or --generate to have one generated",
        assert: "Refuses rather than generating one implicitly",
      },
      {
        id: "P9",
        title: "Rotate with a generated value",
        surface: "cli",
        gate: "none",
        command: `rocketvault secrets rotation rotate --secret-id <secret-id> --policy-id <policy-id> \\
  --generate --length 24 --vault prod`,
        expected: "Secret rotated successfully.",
        assert: "Rotated",
      },
      {
        id: "P10",
        title: "TRIGGERED_BY always reads manual, even for scheduled rotations",
        surface: "cli",
        gate: "none",
        command: `rocketvault secrets rotation history --secret-id <secret-id> --vault prod`,
        expected: `ROTATED_AT        TRIGGERED_BY  PREV_VERSION  NEW_VERSION  NOTES
2026-08-25 22:24  manual        1             2

Found 1 rotation events`,
        assert: "manual — and it will read manual for scheduler runs too",
        flag: "gap",
        why: "`model.TriggerScheduled` is defined but never referenced anywhere outside `model/rotation.go`. Both the CLI's manual `rotate` and the background scheduler's own automatic path funnel through the same `PerformManualRotation`, which unconditionally sets `TriggeredBy: model.TriggerManual` — there is no branch that would ever write `scheduled`.",
        verify: {
          look: "The `ROTATED_AT` timestamp and the version numbers reflect when and how many times rotation has run in this instance, not the literal `2026-08-25 22:24` / `1` / `2` shown here. The only fixed part of the row that must match exactly is `TRIGGERED_BY` reading `manual`.",
        },
        source:
          "model/rotation.go:59-60; internal/services/secrets/rotation_service.go:472; internal/services/secrets/scheduler_service.go:177-189,247; VAULT_USER_ACCESS_JOURNEYS_v3.md § Journey P",
      },
      {
        id: "P11",
        title: "rotation update is a partial update",
        surface: "cli",
        gate: "none",
        command: `rocketvault secrets rotation update --id <policy-id> --auto-rotate=false --vault prod`,
        expected: "Rotation policy updated successfully.",
        assert: "Only the flags passed change",
        notes:
          "Contrast with `keys rotation-policy set` (C14), which is a full replace. Two rotation-policy surfaces, two contracts.",
        related: [{ id: "C14", rel: "contrasts" }],
      },
      {
        id: "P12",
        title: "Unassign twice: the second time errors",
        surface: "cli",
        gate: "none",
        command: `rocketvault secrets rotation unassign --policy-id <policy-id> --secret-id <secret-id> --vault prod
rocketvault secrets rotation unassign --policy-id <policy-id> --secret-id <secret-id> --vault prod`,
        expected: `Policy removed from secret successfully.
Error: failed to remove policy from secret: failed to remove policy from secret: policy assignment not found`,
        assert: "First succeeds, second errors",
      },
      {
        id: "P13",
        title: "Delete twice: the second time errors",
        surface: "cli",
        gate: "none",
        command: `rocketvault secrets rotation delete --id <policy-id> --vault prod
rocketvault secrets rotation delete --id <policy-id> --vault prod`,
        expected: `Rotation policy deleted successfully.
Error: failed to delete rotation policy: failed to delete rotation policy: rotation policy not found`,
        assert: "First succeeds, second errors",
      },
      {
        id: "P14",
        title: "History outlives the policy that caused it",
        surface: "cli",
        gate: "none",
        command: `rocketvault secrets rotation history --secret-id <secret-id> --vault prod`,
        expected:
          "The manual entry is still there, now with a PolicyID that no longer resolves.",
        assert: "Past events survive; by design",
        why: "`DeletePolicy` deletes only the `rotation_policies` row — it never touches `secret_rotation_history`. Every past entry survives with a `policy_id` that no longer resolves to anything.",
        source: "internal/services/secrets/rotation_service.go:262-273",
      },
      {
        id: "P15",
        title: "No HTTP route exists — 404, not 403",
        surface: "http",
        gate: "none",
        command: `curl -s -o /dev/null -w '%{http_code}\\n' $BASE/vaults/prod/secrets/rotation-policies \\
  -H "Authorization: Bearer $WREN_TOKEN"
curl -s -o /dev/null -w '%{http_code}\\n' $BASE/secrets/rotation \\
  -H "Authorization: Bearer $WREN_TOKEN"`,
        expected: `404
404`,
        assert: "404 on both — there is no authorization decision to make",
        flag: "gap",
        why: "`api/secrets.go` registers no route containing `rotation` at all — this feature has no HTTP handler to gate, so `PolicyMiddleware` never runs for it and there is no 403 to produce, only the router's own 404 for an unmatched path.",
        source: "api/secrets.go (no rotation route registered)",
      },
    ],
  },
  {
    key: "Q",
    title: "Certificate manager issues, chains and retires a TLS certificate",
    actor: "Noor — certificate_manager",
    premise:
      "A certificate is always issued over an existing key, and key creation needs a role Noor does not hold. Issuing or renewing also needs `keys/sign` in the vault, a key Noor owns, and a usable key. The divergence to catch: `renew` checks `certificates/create`, not `certificates/update`, unlike every other mutating cert command.",
    cases: [
      {
        id: "Q1",
        title: "Create the account with the required global role",
        surface: "cli",
        gate: "global-admin",
        command: `rocketvault users create --new-username noor --new-password '<pw>' --new-role certificate_manager

rocketvault vault-access grant noor --role "Key Vault Certificates Officer" --vault prod`,
        expected: "The user exists and holds Certificates Officer in prod.",
        assert:
          "Certificates Officer is full control, and is one of Wren's eight",
        why: "The eight roles a Data Access Administrator like Wren may grant without being a global admin are fixed by `RoleAssignmentService.AssignRole`'s allow-list check, `ErrRoleNotGrantable` otherwise. `Key Vault Certificates Officer` is one of the eight. Journey G enumerates the full list and shows all three excluded roles being refused — `Key Vault Purge Operator`, `Key Vault Data Access Administrator` and `Key Vault Certificate User`.",
        source:
          "internal/services/authorization/role_assignment_service.go:19-24,127; VAULT_USER_ACCESS_JOURNEYS_v3.md § Journey G — the eight-role allow-list (lines 505-546)",
      },
      {
        id: "Q2",
        title: "certificate_manager does not cover key creation",
        surface: "cli",
        gate: "global-role",
        command: `rocketvault keys create --name checkout-tls-leaf --type RSA --bits 2048 --vault prod`,
        expected: "Error: forbidden: requires admin or crypto_manager role",
        assert: "She cannot self-serve the key her certificate needs",
        why: "`keys create`'s global-role gate checks `HasAnyRole(admin, crypto_manager)` against the caller's claims before any vault check runs. Noor's `certificate_manager` role is not in that list, so she is denied here regardless of what she holds in `prod`.",
        related: [{ id: "C1", rel: "contrasts" }],
        source: "cmd/keys/create.go:72",
      },
      {
        id: "Q3",
        title: "Noor creates her own keys once Priya widens her roles",
        surface: "cli",
        gate: "global-role",
        precondition:
          "Run as Priya first, then as Noor after logging in again.",
        command: `rocketvault users update <noor-user-id> --new-role certificate_manager --new-role crypto_manager
rocketvault vault-access grant noor --role "Key Vault Crypto Officer" --vault prod

rocketvault keys create --name checkout-ca-key --type RSA --bits 4096 --vault prod
rocketvault keys create --name checkout-tls-leaf --type ECDSA --curve P-384 --vault prod`,
        expected: "Two keys, created by Noor.",
        assert: "The keys the certificates use are owned by Noor, not by Sofia",
        why: "Issuing a certificate requires the caller to own the signing key (the B32 owner check in `ValidateKeyOwnership`), and no `cmd/keys` command changes a key's owner. Key Vault Crypto Officer holds `keys/create` and `keys/sign`. A role change ends the user's sessions, so Noor logs in again.",
        related: [{ id: "Q2", rel: "depends" }],
        source:
          "internal/services/certificates/certificate_service.go:1388-1391; model/azure_roles.go:205-211; internal/services/users/user_service.go:397-418",
      },
      {
        id: "Q4",
        title: "Self-signed certificate over an existing key",
        surface: "cli",
        gate: "global-role",
        precondition: "Run as Noor, over a key Noor created in Q3.",
        command: `rocketvault certificates create --name checkout-tls-selfsigned \\
  --key-id <checkout-tls-leaf-key-id> --validity-days 365 --tags prod,tls --vault prod`,
        expected: `ID    Name                       Created
<id>  checkout-tls-selfsigned    2026-08-25T...`,
        assert: "Created",
      },
      {
        id: "Q5",
        title: "Flag validation runs before authorization or key lookup",
        surface: "cli",
        gate: "validation",
        command: `rocketvault certificates create --key-id <checkout-tls-leaf-key-id> --validity-days 365 --vault prod`,
        expected: "Error: name, key-id, and validity-days are required",
        assert: "Rejected on the missing name, before any auth check",
      },
      {
        id: "Q6",
        title: "Stand up a CA, then issue a leaf against it",
        surface: "cli",
        gate: "global-role",
        command: `rocketvault certificates create --name checkout-root-ca \\
  --key-id <checkout-ca-key-id> --is-ca --validity-days 3650 --vault prod

rocketvault certificates create --name checkout-tls-chained \\
  --key-id <checkout-tls-leaf-key-id> --ca-cert-id <ca-cert-id> \\
  --validity-days 90 --tags prod,tls --auto-renew --renewal-days 30 --vault prod`,
        expected: "A CA certificate, then a leaf signed by it.",
        assert: "Both created; the leaf chains to the CA",
      },
      {
        id: "Q7",
        title: "--is-ca and --ca-cert-id are mutually exclusive",
        surface: "cli",
        gate: "validation",
        command: `rocketvault certificates create --name broken --key-id <checkout-tls-leaf-key-id> \\
  --is-ca --ca-cert-id <ca-cert-id> --validity-days 90 --vault prod`,
        expected:
          "Error: failed to create certificate: cannot issue a CA-signed certificate as a CA: intermediate CA certificates are not supported",
        assert: "Refused — a cert is either the CA or signed by one",
      },
      {
        id: "Q8",
        title: "--auto-renew only arms the scheduler",
        surface: "cli",
        gate: "none",
        command: `# Confirm the scheduler ran. Do not expect a notification.`,
        expected: "No notification of any kind is delivered.",
        assert: "Journey C's finding holds for certificates too",
        flag: "gap",
      },
      {
        id: "Q9",
        title: "certificate is an alias for certificates everywhere",
        surface: "cli",
        gate: "none",
        command: `rocketvault certificate list --vault prod --output json
rocketvault certificate get <ca-cert-id> --vault prod`,
        expected: `ID    Name              Tags  Expires        AutoRenew  Created
<id>  checkout-root-ca        2036-08-23...  false      2026-08-25T...`,
        assert: "Singular and plural both work",
        why: 'The top-level `certificates` command is registered with `Aliases: []string{"certificate"}`, so every subcommand resolves identically under either name — there is no separate singular command tree to drift out of sync with the plural one.',
        source: "cmd/certificates.go:34",
      },
      {
        id: "Q10",
        title: "Reads need no global role",
        surface: "cli",
        gate: "vault-role",
        precondition: "Run as daeho, holding only Key Vault Reader in prod.",
        command: `rocketvault certificate list --vault prod`,
        expected: "The listing renders.",
        assert: "Works without certificate_manager",
        why: "`certificate list` and `certificate get` call `vaultcli.RequireDataAction` directly and never call `common.HasAnyRole` — the global-role gate Correction 8 documents for every mutating certificate command simply is not in these two handlers.",
        source: "cmd/certificates/list.go:64; cmd/certificates/get.go:70",
      },
      {
        id: "Q11",
        title: "Update is metadata only and never re-signs",
        surface: "cli",
        gate: "global-role",
        command: `rocketvault certificate update <leaf-cert-id> --tags prod,tls,rotated-2026-08 --vault prod
rocketvault certificate get <leaf-cert-id> --vault prod --output json | jq .name`,
        expected: "Certificate updated successfully. The name is unchanged.",
        assert: "Only the flags passed take effect",
        why: "`UpdateCertificate` copies the existing record and overwrites the metadata fields whose request pointers are non-nil. It never touches the stored `Certificate` PEM bytes or the key material, so there is nothing in this code path that could re-sign anything.",
        source: "internal/services/certificates/certificate_service.go:772-815",
      },
      {
        id: "Q12",
        title: "Renew adds a new version over the same key and id",
        surface: "cli",
        gate: "global-role",
        command: `rocketvault certificate renew <leaf-cert-id> --validity-days 180 --vault prod`,
        expected: `Certificate renewed successfully!
Certificate ID: <leaf-cert-id>
Version: <previous version + 1>
Validity: 180 days`,
        assert: "Same id, same key, next version, new validity",
        why: "`RenewCertificate` archives the current version under its own number and bumps the same row to the next version in one transaction (`ArchiveAndRenew`), so the ID and the `KeyID` are unchanged while the certificate body and validity are new. The command prints the new version number.",
        source:
          "internal/services/certificates/certificate_service.go:1057-1068,1171, cmd/certificates/renew.go:96-104",
      },
      {
        id: "Q13",
        title: "Renew checks certificates/create, not certificates/update",
        surface: "cli",
        gate: "vault-role",
        precondition: `rocketvault vault-access grant noor --role "Key Vault Certificate User" --vault staging`,
        command: `rocketvault certificate renew <staging-cert-id> --vault staging`,
        expected:
          "Error: failed to renew certificate: forbidden: no role grants Microsoft.KeyVault/vaults/certificates/create in this vault",
        assert: "The action named in the error is create, not update",
        flag: "divergence",
        notes:
          "Unlike every other mutating cert command. A principal with update but not create can run `certificate update` and not `certificate renew`.",
        why: "`certificate renew`'s `RunE` authorizes with `model.ActionCertificatesCreate`, not `ActionCertificatesUpdate` — the only mutating certificate command that does — and then requires `keys/sign` as well (Q18). A principal holding `Key Vault Certificate User` (read-only) or any role granting update-but-not-create fails here even though `certificate update` would succeed for that same principal.",
        related: [{ id: "Q12", rel: "contrasts" }],
        source: "cmd/certificates/renew.go:58,83",
      },
      {
        id: "Q14",
        title: "An expired or disabled CA blocks renewal of what it signed",
        surface: "cli",
        gate: "none",
        command: `rocketvault certificate renew <leaf-signed-by-expired-ca> --vault prod`,
        expected: "Refused — never silently downgraded to self-signed.",
        assert: "Refusal, not a silent self-signed fallback",
        why: "Renewing a CA-signed certificate re-fetches the signing CA through `GetCertificate`, which enforces `cert.IsAccessible()` — not disabled, inside its validity window — and returns `ErrCertLifecycleDenied` ('certificate is disabled or outside its valid time window') if that fails. `renewCASignedBody` wraps that as 'signing CA %s is unusable' and refuses outright; there is no branch that falls back to issuing self-signed instead.",
        source: "internal/services/certificates/certificate_service.go:936-950",
      },
      {
        id: "Q15",
        title: "Delete is soft-delete, and the row survives",
        surface: "cli",
        gate: "global-role",
        command: `rocketvault certificate delete <leaf-cert-id> --vault prod
rocketvault certificate list --vault prod --output json | jq '[.[] | select(.id=="<leaf-cert-id>")]'
rocketvault certificate get <leaf-cert-id> --vault prod`,
        expected: `Certificate deleted successfully: <leaf-cert-id>
[]
Error: failed to get certificate: certificate not found: certificate not found or access denied`,
        assert: "Gone from listing and get; still a soft-deleted row",
        related: [{ id: "Q16", rel: "depends" }],
      },
      {
        id: "Q16",
        title: "Recovery needs REST — the CLI has no subcommand",
        surface: "http",
        gate: "vault-role",
        command: `curl -s -X POST $BASE/vaults/prod/deleted/certificates/<leaf-cert-id>/restore \\
  -H "Authorization: Bearer $NOOR_OR_ADMIN_TOKEN"`,
        expected: "The certificate is restored.",
        assert: "REST-only, mirroring the key-lifecycle gaps",
        flag: "gap",
        verify: {
          look: "Follow with `rocketvault certificate get <leaf-cert-id> --vault prod` and confirm it succeeds again — the restore call returning is not itself proof the certificate is usable, only that the row's `deleted_at` was cleared.",
        },
        source: "api/soft_delete.go:329",
      },
      {
        id: "Q17",
        title: "Another user's key is refused even with every role",
        surface: "cli",
        gate: "none",
        flag: "trap",
        notes:
          "The refusal comes from the key owner check, not from any of the three gates, so `gate` is `none`. Holding every role in the vault does not get past it.",
        precondition:
          "Run as Noor, holding Certificates Officer and Crypto Officer in prod. Sofia created sofia-owned-key in prod.",
        command: `rocketvault certificates create --name not-allowed \\
  --key-id <sofia-owned-key-id> --validity-days 365 --vault prod`,
        expected:
          "Error: failed to create certificate: forbidden: cannot use other users' keys",
        assert: "Refused by the owner check, not by a role",
        why: "`ValidateKeyOwnership` compares the key's `UserID` with the caller and returns `ErrSigningKeyForbidden`, whose text is `forbidden: cannot use other users' keys`. The vault-role checks passed before it ran.",
        related: [{ id: "Q3", rel: "depends" }],
        source:
          "internal/services/certificates/certificate_service.go:1388-1391; cmd/certificates/create.go:110",
      },
      {
        id: "Q18",
        title: "Certificates Officer alone cannot issue or renew",
        surface: "cli",
        gate: "vault-role",
        precondition:
          "Run as Noor in dev, where Priya granted her Key Vault Certificates Officer and nothing else.",
        command: `rocketvault vault-access grant noor --role "Key Vault Certificates Officer" --vault dev
rocketvault certificate renew <dev-cert-id> --vault dev`,
        expected:
          "Error: failed to renew certificate: forbidden: no role grants Microsoft.KeyVault/vaults/keys/sign/action in this vault",
        assert:
          "The action named in the error is keys/sign, not certificates/create",
        flag: "trap",
        notes:
          "Certificates Officer reads as full control of certificates, yet it cannot issue or renew. Granting Key Vault Crypto User in dev clears it. `certificate create` is refused the same way.",
        why: "`certificate renew` and `certificate create` call `s.RequireAlso(model.ActionKeysSign, model.OpSign)` right after `s.Authorize()`, before the certificate is looked up. Key Vault Certificates Officer holds no `keys/sign`; Administrator, Crypto Officer and Crypto User do. Over REST the same refusal is a 403 audited as `denied`, while the CLI audits it as `failed`.",
        related: [{ id: "Q13", rel: "contrasts" }],
        source:
          "cmd/certificates/renew.go:83; cmd/certificates/create.go:110; model/azure_roles.go:170-217; api/certificates.go:287-303; api/context.go:124-130; cmd/vaultcli/session.go:196-209",
      },
    ],
  },
  {
    key: "R",
    title: "Disaster recovery: scheduled backups and a post-rotation restore",
    actor: "Priya — admin only, with no vault scoping at all",
    premise:
      "A backup is one whole-instance JSON file. The trap is that a backup taken before a master-key rotation cannot be restored after it, because both the file wrapper and the column ciphertext are sealed with the same key.",
    cases: [
      {
        id: "R1",
        title: "backup is a pure global-admin gate with no vault lookup",
        surface: "cli",
        gate: "global-admin",
        precondition: "Run as marcus, holding secrets_manager.",
        command: `rocketvault backup list --dir /var/backups/rocketvault`,
        expected: "Error: forbidden: requires admin role",
        assert: "Denied — --vault is accepted but never read",
        notes:
          "An operator with a role in one vault cannot use these commands regardless of what they pass to `--vault`.",
        why: "`requireBackupAdmin` checks only the global `admin` role, with no vault lookup at all. The inherited `--vault` flag is accepted but never read, so an operator holding a role in only one vault cannot use these commands no matter what they pass to it.",
        source: "VAULT_USER_ACCESS_JOURNEYS_v3.md § Journey R",
      },
      {
        id: "R2",
        title: "Create a backup by hand before trusting cron",
        surface: "cli",
        gate: "global-admin",
        command: `rocketvault backup create --file /var/backups/rocketvault/nightly-2026-08-25.backup`,
        expected: `Backup created successfully.
File: /var/backups/rocketvault/nightly-2026-08-25.backup
Encrypted: true`,
        assert: "Encrypted: true — this line is your real confirmation",
      },
      {
        id: "R3",
        title: "The destination flag is --file, not --output",
        surface: "cli",
        gate: "validation",
        command: `rocketvault backup create --output /var/backups/x.backup`,
        expected:
          "Treated as root's persistent --output format selector, and rejected as an invalid format.",
        assert: "--output is the table/json/yaml selector, not a path",
        flag: "trap",
        notes: "See § B48.",
        why: "`backup create` briefly defined its own local `--output` flag for the file destination, which collided with the root command's persistent `--output` (the table/json/yaml format selector). It was renamed to `--file`/`-f` on 2026-08-22 to resolve the collision.",
        source: "VAULT_USER_ACCESS_JOURNEYS_v3.md § Journey R",
      },
      {
        id: "R4",
        title: "backup list shows dashes for encrypted backups",
        surface: "cli",
        gate: "global-admin",
        command: `rocketvault backup list --dir /var/backups/rocketvault`,
        expected: `TIMESTAMP  VERSION  TABLES  RECORDS  ENCRYPTED  FILE                        SIZE    MODIFIED
-          -        -       -        true       nightly-2026-08-25.backup   482113  2026-08-25 02:00:01

Found 1 backup files in /var/backups/rocketvault`,
        assert: "The dashes are correct, not broken",
        notes: "It is for inventory, not verification.",
        why: "`backup list` never touches the master key, so it cannot decrypt a backup file to read its timestamp, version, table or record counts. Only the filename, size and modification time come from the filesystem — the dashes are the correct output for an encrypted backup, not a bug.",
        source: "VAULT_USER_ACCESS_JOURNEYS_v3.md § Journey R",
      },
      {
        id: "R5",
        title: "There is no built-in scheduler",
        surface: "local",
        gate: "none",
        command: `# /etc/cron.d/rocketvault-backup
0 2 * * * root cd /opt/rocketvault && ./rocketvault backup create \\
  --file /var/backups/rocketvault/nightly-$(date +\\%F).backup \\
  >> /var/log/rv-backup.log 2>&1`,
        expected:
          "No --schedule flag, no daemon. “Scheduled” means an external cron or systemd timer.",
        assert: "The cached session refreshes itself, so cron keeps working",
        flag: "gap",
        why: "The cached CLI session refreshes itself transparently via its refresh token, so a cron job started non-interactively keeps authenticating as long as someone logged in at least once and that refresh token has not itself expired.",
        source: "VAULT_USER_ACCESS_JOURNEYS_v3.md § Journey R",
      },
      {
        id: "R6",
        title: "Restoring across a master-key rotation fails on the auth tag",
        surface: "cli",
        gate: "global-admin",
        precondition:
          "The backup was taken before `master-key rotate` ran; config now holds the new key.",
        command: `rocketvault backup restore --file /var/backups/rocketvault/nightly-2026-08-25.backup`,
        expected: `Error: restore failed: failed to read backup file: failed to decrypt backup: failed to decrypt: cipher: message authentication failed`,
        assert: "GCM auth-tag failure",
        flag: "trap",
        notes:
          "Take a fresh backup immediately after any master-key rotation; the ones taken before it are readable only with the old key.",
        why: "Column-level encryption (`secrets.value` and its siblings) and a backup file's own `--encrypt` wrapper are sealed with the exact same `master_key` from configuration, via `common.EncryptSecret`/`DecryptSecret`. `master-key rotate` re-encrypts every live row onto the new key but leaves existing backup files sealed under the old one, so a backup taken before rotation and a server now holding the new key produce the same GCM auth-tag failure regardless of which layer fails first.",
        related: [{ id: "S9", rel: "depends" }],
        source: "VAULT_USER_ACCESS_JOURNEYS_v3.md § Journey R — The incident",
      },
      {
        id: "R7",
        title: "The restore succeeds under the pre-rotation key",
        surface: "cli",
        gate: "global-admin",
        command: `export MASTER_KEY="<the pre-rotation key, saved before the rotation>"

rocketvault backup restore --file /var/backups/rocketvault/nightly-2026-08-25.backup`,
        expected: `Are you sure you want to continue? (type 'yes' to confirm): yes
Database restored successfully from /var/backups/rocketvault/nightly-2026-08-25.backup`,
        assert: "Restores once pointed at the right key",
        why: "Losing the pre-rotation master key permanently is unrecoverable, not merely inconvenient: every secret value, key PEM and certificate private key restored from that backup is column-level ciphertext sealed under the same lost key, independent of the file's own `--encrypt` wrapper. There is no recovery path if it's gone.",
        related: [{ id: "R6", rel: "depends" }],
        source: "VAULT_USER_ACCESS_JOURNEYS_v3.md § Journey R — The incident",
      },
      {
        id: "R8",
        title: "The restore does not undo the rotation",
        surface: "cli",
        gate: "none",
        command: `# Decide deliberately: re-run master-key rotate onto the new key,
# or leave the config on the old key.`,
        expected:
          "The restored rows are sealed under the old key while MASTER_KEY still points at it.",
        assert: "A deliberate decision is required before restarting",
        flag: "trap",
        why: "`backup restore` rewrites the `secrets`/`keys`/`certificates` tables from the file, which are sealed under whatever key was active when the backup was taken — the old key. It has no awareness of `master-key rotate` and does nothing to the running server's `MASTER_KEY`, so after a restore the data and the running config point at two different keys until someone reconciles them by hand.",
        source: "VAULT_USER_ACCESS_JOURNEYS_v3.md § Journey R — The incident",
      },
      {
        id: "R9",
        title: "Restore only refills tables present in the file",
        surface: "cli",
        gate: "none",
        command: `# A table added by a migration after the backup was taken is untouched.`,
        expected: "Tables the backup does not contain are left alone.",
        assert: "Restoring old data does not roll back the schema",
        why: "`RestoreBackup` only writes tables actually present in the backup file. A table added by a schema migration after the backup was taken has no rows in the file to restore, so it is left untouched — restoring an old backup rolls back your data, not your schema.",
        source: "VAULT_USER_ACCESS_JOURNEYS_v3.md § Journey R — The incident",
      },
      {
        id: "R10",
        title: "Sessions are wiped and refilled like every other table",
        surface: "cli",
        gate: "none",
        command: `sudo systemctl start rocketvault
# Have everyone re-run "rocketvault users login".`,
        expected:
          "Server-side session state created after the backup point is gone.",
        assert: "Everyone must log in again",
        why: "`sessions` is a table like any other in the backup file. Restore wipes and refills it along with everything else, so any session created after the backup's point in time is gone and every user must log in again.",
        source: "VAULT_USER_ACCESS_JOURNEYS_v3.md § Journey R — The incident",
      },
      {
        id: "R11",
        title: "Restore has no dry-run and no selective mode",
        surface: "cli",
        gate: "none",
        command: `rocketvault backup restore --dry-run --file <backup>`,
        expected:
          "No such flag. It is whole-file, whole-transaction, or nothing.",
        assert: "No dry-run, no partial restore",
        flag: "gap",
        notes:
          "A backup is whole-instance: every vault, every table verbatim, including soft-deleted rows, users, role assignments, sessions and the audit log. The inherited `--vault` flag is accepted but ignored.",
      },
    ],
  },
  {
    key: "S",
    title: "Rotating the master key after an infrastructure departure",
    actor: "Priya — admin only; crypto_manager and secrets_manager get no pass",
    premise:
      "Revoking role assignments does nothing about a key someone copied off the host. This is the only remedy — and it is not atomic, not enforced offline, and does not write the new key back to your config.",
    cases: [
      {
        id: "S1",
        title: "Non-admins cannot even dry-run it",
        surface: "cli",
        gate: "global-admin",
        precondition: "Run as daeho, global role user.",
        command: `rocketvault master-key rotate --new-key-env NEW_MASTER_KEY --dry-run`,
        expected: "Error: forbidden: requires admin role",
        assert: "Denied at --dry-run, before anything is read",
        why: "`master-key rotate` checks only the global `admin` role. Unlike the Correction 8 gate on `keys`/`secrets` commands, holding `crypto_manager` or `secrets_manager` does not grant a pass here — the check runs before anything else, including `--dry-run`.",
        related: [{ id: "S9", rel: "contrasts" }],
        source: "VAULT_USER_ACCESS_JOURNEYS_v3.md § Journey S",
      },
      {
        id: "S2",
        title: "A stray exported MASTER_KEY silently becomes the old key",
        surface: "cli",
        gate: "validation",
        precondition:
          "Export both MASTER_KEY and NEW_MASTER_KEY to the same value.",
        command: `rocketvault master-key rotate --new-key-env NEW_MASTER_KEY --dry-run`,
        expected: `Error: the new master key is identical to the old one (old key source: config file
(master_key)); note that an exported MASTER_KEY environment variable takes
precedence over the config file`,
        assert:
          "The label says “config file” even when the env var supplied it",
        flag: "trap",
        notes:
          "The error's own source label is misleading here — read the second clause.",
        why: 'Viper resolves an exported `MASTER_KEY` environment variable before it reads `.rocketvault.yaml`, so leaving `--old-key-env` unset does not fall back to the config file if a stray `MASTER_KEY` is exported — it silently becomes the old key instead. The error message\'s own label always reads "config file (master_key)" regardless of which source actually supplied the value, so the label itself cannot be trusted here.',
        source: "VAULT_USER_ACCESS_JOURNEYS_v3.md § Journey S — Step 1",
      },
      {
        id: "S3",
        title: "Nothing stops you running this against a live server",
        surface: "cli",
        gate: "none",
        command: `# The --help text and the runbook both say to stop the server.
# runMasterKeyRotate never checks for a running process, lock or PID file.`,
        expected: "It runs. The guard is narrower and comes later — see S4.",
        assert: "Server-stopped is advisory, not enforced",
        flag: "gap",
        why: "`runMasterKeyRotate` never checks whether the server process is running, holds a lock, or has a PID file. The `--help` text and the runbook both say to stop the server first, but that is advice only — nothing in the code enforces it.",
        related: [{ id: "S4", rel: "contrasts" }],
        source:
          "VAULT_USER_ACCESS_JOURNEYS_v3.md § Journey S — Nothing in the code stops you from running this against a live server",
      },
      {
        id: "S4",
        title: "A row rewritten mid-run aborts its batch",
        surface: "cli",
        gate: "none",
        command: `# Every UPDATE is qualified with AND <column> = ? bound to the ciphertext
# read during the plan pass.`,
        expected: `Error: master key rotation failed: keys.value: row [<id>] changed while the rotation
was running (0 rows updated, expected 1) — stop the RocketVault server and re-run`,
        assert: "Aborts rather than clobbering a concurrent write",
        notes:
          "The realistic outcome of running this live is a **partially rotated instance** — `secrets` done, `keys` half-done — not corruption.",
        why: "Every `UPDATE` in `rekey.go`'s `applyBatch` is qualified with `AND <column> = ?` bound to the exact ciphertext read during the earlier plan pass, so a row rewritten by a still-live server between plan and apply matches zero rows and the whole batch aborts rather than clobbering the write. Targets are processed one table at a time (`secrets` → `secret_versions` → `keys` → `key_versions` → `certificates`), and batches within a target commit independently, so running this against a live server realistically leaves a partially rotated instance rather than corrupting anything.",
        source:
          "VAULT_USER_ACCESS_JOURNEYS_v3.md § Journey S — Nothing in the code stops you from running this against a live server",
      },
      {
        id: "S5",
        title: "Back up first — there is no inverse command",
        surface: "local",
        gate: "none",
        command: `cp dev-rocketvault.db dev-rocketvault.db.pre-rotation-2026-08-25   # SQLite
# pg_dump "$DATABASE_URL" > rocketvault-pre-rotation.sql           # Postgres`,
        expected: "A copy on disk.",
        assert: "This plus the still-valid old key is the only rollback path",
      },
      {
        id: "S6",
        title: "Read the dry-run report before touching anything",
        surface: "cli",
        gate: "global-admin",
        command: `rocketvault master-key rotate --new-key-env NEW_MASTER_KEY --dry-run`,
        expected: `Old master key source: config file (master_key)
New master key source: environment variable NEW_MASTER_KEY
Mode: DRY RUN (no rows will be written)

TABLE            COLUMN       ROWS  RE-ENCRYPTED  ALREADY NEW KEY  SKIPPED (HSM)
secrets          value        3     3             0                0
secret_versions  value        0     0             0                0
keys             value        1     0             0                1
key_versions     value        0     0             0                0
certificates     private_key  0     0             0                0

Total rows re-encrypted: 3

Dry run complete. No rows were modified.`,
        assert: "Row counts match what you expect to be in the instance",
      },
      {
        id: "S7",
        title: "HSM-backed keys are skipped and not covered by this rotation",
        surface: "cli",
        gate: "none",
        command: `# SKIPPED (HSM) counts key rows whose value is a pkcs11: token label
# rather than sealed PEM.`,
        expected:
          "Those rows are untouched, because the material never left the HSM.",
        assert: "HSM key exposure is a separate PKCS#11/PIN problem",
        why: "`SKIPPED (HSM)` counts key rows whose `value` column holds a `pkcs11:`-prefixed token label rather than sealed PEM. That key material never left the HSM, so there is nothing in the database for this command to re-encrypt — HSM-backed keys are not covered by `master-key rotate` at all, and a departing engineer's exposure to them is a separate PKCS#11/PIN-rotation problem.",
        source: "VAULT_USER_ACCESS_JOURNEYS_v3.md § Journey S — Step 3",
      },
      {
        id: "S8",
        title: "Anything but the exact string yes aborts — and exits 0",
        surface: "cli",
        gate: "validation",
        command: `echo "" | rocketvault master-key rotate --new-key-env NEW_MASTER_KEY
echo $?`,
        expected: `Aborted.
0`,
        assert: "Exit code 0 on an aborted, no-op rotation",
        flag: "trap",
        notes: "For unattended runs pass `--yes` rather than piping an answer.",
        why: "Typing anything other than the exact string `yes` at the confirmation prompt — including a blank line — prints `Aborted.` and exits `0`. A maintenance script that only checks the exit code reads an aborted, no-op rotation as a success. For unattended runs, pass `--yes` explicitly rather than piping an answer to the prompt.",
        source:
          "VAULT_USER_ACCESS_JOURNEYS_v3.md § Journey S — Step 4 — Run it for real",
      },
      {
        id: "S9",
        title: "Run it for real",
        surface: "cli",
        gate: "global-admin",
        command: `rocketvault master-key rotate --new-key-env NEW_MASTER_KEY --yes`,
        expected: `Rotation complete. Set the new key as master_key in the configuration (or as the
MASTER_KEY environment variable) and restart the server.
Reminder: existing database backup files were sealed under the old key and are not
affected by this rotation — they will not restore once the old key is retired.`,
        assert: "Same counts as the dry run",
        verify: {
          look: "The table reprints before the success message with the identical ROWS / RE-ENCRYPTED / ALREADY NEW KEY / SKIPPED (HSM) counts as S6's dry run — compare them line by line rather than only checking for the success message.",
        },
        after:
          "The database now holds the new key, but the running server is still configured for the old one. Nothing writes the new key back to `.rocketvault.yaml`, and nothing restarts the server — both are manual steps, covered next.",
        related: [{ id: "S6", rel: "depends" }],
        source:
          "VAULT_USER_ACCESS_JOURNEYS_v3.md § Journey S — Step 4 — Run it for real; VAULT_USER_ACCESS_JOURNEYS_v3.md § Journey S — Step 5 — Finish the job by hand",
      },
      {
        id: "S10",
        title: "Re-running with the same key pair is safe",
        surface: "cli",
        gate: "none",
        command: `rocketvault master-key rotate --new-key-env NEW_MASTER_KEY --yes`,
        expected:
          "Rows already on the new key are counted under ALREADY NEW KEY and skipped.",
        assert: "Safe to resume — which is not the same as atomic",
        why: "`classify()` recognizes rows already sealed under the new key and skips them, so re-running the same `--new-key-env`/old-key pair after an interruption picks up only what wasn't finished — those rows are counted under `ALREADY NEW KEY`. That makes resuming safe, but it is not the same guarantee as the whole run being one atomic transaction.",
        source:
          "VAULT_USER_ACCESS_JOURNEYS_v3.md § Journey S — The compromise-driven trade-off this journey exists for",
      },
      {
        id: "S11",
        title: "The new key is never written back to the config",
        surface: "local",
        gate: "none",
        command: `# .rocketvault.yaml
master_key: "<value of $NEW_MASTER_KEY>"`,
        expected: "You edit this by hand, always.",
        assert: "Manual edit required",
        flag: "gap",
      },
      {
        id: "S12",
        title: "Verify with a command that actually decrypts",
        surface: "cli",
        gate: "vault-role",
        command: `rocketvault serve
rocketvault secrets list --vault default`,
        expected: "A clean read, which proves config and database agree.",
        assert: "Use secrets list, not certificates list",
        flag: "trap",
        notes:
          "A clean `secrets list` is the real proof; a clean `certificates list` is not.",
        why: "`ListCertificates`/`GetCertificate` never touch the `private_key` column, so a clean `certificates list` after restarting proves nothing about whether the rotation and the running config actually agree. `secrets list` decrypts every value it returns, so a clean read there is real proof the two agree.",
        source:
          "VAULT_USER_ACCESS_JOURNEYS_v3.md § Journey S — Step 5 — Finish the job by hand",
      },
    ],
  },
  {
    key: "T",
    title: "Working across prod, staging and dev from one laptop",
    actor: "Priya — three separate RocketVault deployments",
    premise:
      "A context is the lowest-precedence, easiest-to-forget source of a target, which is exactly why it causes surprises days after it was set. Most command groups fail closed; `secrets` does not.",
    cases: [
      {
        id: "T1",
        title: "Add three contexts; only --server is required",
        surface: "local",
        gate: "none",
        command: `rocketvault context add prod \\
  --server https://vault.prod.internal \\
  --default-username ops-oncall --default-vault prod

rocketvault context add staging --server https://vault.staging.internal:8443 --default-vault staging
rocketvault context add dev --server http://localhost:8774 --default-vault dev

rocketvault context list`,
        expected: `Name     Server                               Default Username  Default Vault  Current
dev      http://localhost:8774                                  dev
prod     https://vault.prod.internal          ops-oncall        prod
staging  https://vault.staging.internal:8443                    staging`,
        assert: "Three rows; no Current marked yet",
        why: "`context add` only ever writes to `~/.rocketvault/contexts.json` — it never dials the server and stores no credentials, so an environment that is currently down still saves cleanly.",
        source: "VAULT_USER_ACCESS_JOURNEYS_v3.md § Journey T",
      },
      {
        id: "T2",
        title: "A missing URL scheme is caught at save time",
        surface: "local",
        gate: "validation",
        command: `rocketvault context add prod --server vault.prod.internal`,
        expected: `Error: --server "vault.prod.internal" needs an http:// or https:// scheme (got "")`,
        assert: "Rejected here, not later as an opaque transport error",
      },
      {
        id: "T3",
        title: "Switch and confirm the active context",
        surface: "local",
        gate: "none",
        command: `rocketvault context use prod
rocketvault context current`,
        expected: "prod -> https://vault.prod.internal",
        assert: "Current reports prod",
      },
      {
        id: "T4",
        title: "Most command groups fail closed with a loud error",
        surface: "cli",
        gate: "none",
        precondition: "The prod context is active.",
        command: `rocketvault keys list --vault dev`,
        expected: `Error: remote mode (--server/ROCKETVAULT_ADDR/context "https://vault.prod.internal") is not yet supported for "rocketvault keys list"; unset it to run against the local instance`,
        assert: "Refused rather than guessing which instance was meant",
        notes:
          "The authority is the `remoteCapableCommands` map in `cmd/root.go` — read that, not a list in a document, including this one.",
        why: "Whether a command group is remote-capable is decided by the `remoteCapableCommands` map in `cmd/root.go`. `keys`, `certificate`, `vaults`, `audit`, and the `users` resource commands have no entry there, so with any context active, `persistentPreRun`'s remote-target guard refuses them outright rather than guessing which instance was meant — this is enforced behavior confirmed against the built binary, not a documentation aspiration.",
        related: [{ id: "T5", rel: "contrasts" }],
        source:
          "VAULT_USER_ACCESS_JOURNEYS_v3.md § Journey T — The mistake this journey is actually about",
      },
      {
        id: "T5",
        title: "A remote-capable group has no such guard",
        surface: "cli",
        gate: "none",
        command: `rocketvault secrets delete <secret-id>`,
        expected: `Error: remote authentication failed - no cached session for server https://vault.prod.internal; run 'rocketvault users login' or pass --username/--password/--totp-code or --client-id/--client-secret`,
        assert: "It tried the remote server rather than refusing",
      },
      {
        id: "T6",
        title: "A remote login becomes the default for later bare commands",
        surface: "cli",
        gate: "none",
        command: `rocketvault users login --username ops-oncall --password '<prod-password>' --totp-code 482913`,
        expected: "Login successful as ops-oncall.",
        assert: "Nothing in the output says it also became the current session",
        flag: "trap",
        why: 'The session is written to a file keyed by server (`srv_https_vault.prod.internal__ops-oncall.json`), which does not disturb any local session for the same username. But the "current session" pointer used by a bare command with no `--server` is a single global file shared between local and remote mode, so logging in against a remote server also makes that server\'s session the one a later bare command reuses — regardless of which vault or environment that later command is meant for.',
        after:
          'The "current" session pointer now points at this remote server\'s session. A later bare command reuses it until it is explicitly cleared — run `rocketvault context current` before trusting a bare command to be local.',
        related: [{ id: "T7", rel: "depends" }],
        source:
          "VAULT_USER_ACCESS_JOURNEYS_v3.md § Journey T — The mistake this journey is actually about",
      },
      {
        id: "T7",
        title: "The next morning: a bare command hits production",
        surface: "cli",
        gate: "none",
        command: `# No --server, no --username, no confirmation prompt.
rocketvault secrets delete <secret-id>`,
        expected: `time="…" level=info msg="Authenticated against remote server" command="Delete a secret by ID" server="https://vault.prod.internal" user=ops-oncall
Secret deleted successfully.`,
        assert:
          "server=… is printed twice on stderr — easy to miss, not silent",
        flag: "trap",
        notes:
          "**Practical rule**: run `rocketvault context current` before any `secrets create/update/delete/import` you intend to be local, and do not discard stderr.",
        why: "The cached session is reused with no server-side revalidation — the CLI only checks the session's local `expires_at`, never re-checking the token against the server before firing the request. A stale `context use` left pointed at `prod` therefore gives every subsequent bare `secrets create/update/delete/import` real blast radius against production, reusing yesterday's login. It is not wholly silent: the target server is named twice in logrus INFO output on stderr, so an operator watching their terminal would see it. The danger is easy to miss, not invisible.",
        related: [
          { id: "T4", rel: "contrasts" },
          { id: "T6", rel: "depends" },
        ],
        source:
          "VAULT_USER_ACCESS_JOURNEYS_v3.md § Journey T — The mistake this journey is actually about",
      },
      {
        id: "T8",
        title: "An omitted --vault falls back to the context default",
        surface: "cli",
        gate: "none",
        command: `rocketvault secrets delete <secret-id>   # prod context active, no --vault`,
        expected:
          "Targets the context's --default-vault (prod), rather than erroring.",
        assert: "Falls back rather than refusing",
        why: "`cmd/secrets/delete.go` reads `target.Vault` — the context's `--default-vault` — only when the `--vault` flag was left empty; it never errors for a missing `--vault`. Combined with T7, an operator who also forgot `--vault` still hits the context's default vault (`prod`), not a safe no-op.",
        related: [{ id: "T7", rel: "depends" }],
        source:
          "VAULT_USER_ACCESS_JOURNEYS_v3.md § Journey T — The mistake this journey is actually about",
      },
      {
        id: "T9",
        title: "logout is scoped to the active target",
        surface: "cli",
        gate: "none",
        command: `rocketvault users logout`,
        expected: "Logged out ops-oncall.",
        assert: "Deletes the remote session file; the local one survives",
        why: "`logout` deletes only the cached session file for the currently active target — with `prod` current it deletes `srv_https_vault.prod.internal__ops-oncall.json` and leaves any local session for the same username alone, and vice versa with no context active. With no `--username` it follows the current-session pointer, but only when that pointer belongs to this server; otherwise it reports `No cached session to log out of.` rather than deleting an unrelated file. It is client-side only — the JWT stays valid on the server until it expires on its own.",
        source:
          "VAULT_USER_ACCESS_JOURNEYS_v3.md § Journey T — Logging out clears one server, not all of them",
      },
      {
        id: "T10",
        title: "Service-account credentials skip the session cache entirely",
        surface: "cli",
        gate: "none",
        command: `export ROCKETVAULT_CLIENT_ID=<client-id>
export ROCKETVAULT_CLIENT_SECRET=<client-secret>
rocketvault secrets list --vault prod`,
        expected: "Authenticates via the OAuth2 client-credentials grant.",
        assert: "Nothing written to ~/.rocketvault/sessions/",
        why: "`ROCKETVAULT_CLIENT_ID`/`ROCKETVAULT_CLIENT_SECRET` (or the equivalent flags) authenticate through the OAuth2 client-credentials grant and take precedence over every other authentication tier — over `--username`/`--password` and over any cached session — writing nothing to `~/.rocketvault/sessions/`.",
        source:
          "VAULT_USER_ACCESS_JOURNEYS_v3.md § Journey T — Unattended auth: no session file at all",
      },
      {
        id: "T11",
        title: "Half a credential pair is a usage error",
        surface: "cli",
        gate: "validation",
        command: `ROCKETVAULT_CLIENT_ID=<client-id> rocketvault secrets list`,
        expected: `Error: remote authentication failed - --client-id given without --client-secret (or ROCKETVAULT_CLIENT_SECRET)`,
        assert: "No silent fallback to an interactive session",
      },
      {
        id: "T12",
        title: "localhost does not get you back into local mode",
        surface: "cli",
        gate: "none",
        command: `rocketvault context use dev
rocketvault keys list --vault dev`,
        expected: `Error: remote mode (--server/ROCKETVAULT_ADDR/context "http://localhost:8774")
       is not yet supported for "rocketvault keys list"; unset it to run
       against the local instance`,
        assert: "The guard does not special-case loopback",
        flag: "trap",
      },
      {
        id: "T13",
        title: "context unset clears the pointer, keeping the saved entries",
        surface: "local",
        gate: "none",
        command: `rocketvault context unset
rocketvault keys list --vault dev`,
        expected: "Works again — no context, no --server, no ROCKETVAULT_ADDR.",
        assert: "Local mode restored; prod/staging/dev still saved",
        why: '`context unset` clears only the "current" pointer. The saved `prod`/`staging`/`dev` entries in `~/.rocketvault/contexts.json` are untouched, and `context use <name>` can switch back to any of them later.',
        source:
          "VAULT_USER_ACCESS_JOURNEYS_v3.md § Journey T — `localhost` doesn't get you out of this",
      },
      {
        id: "T14",
        title: "context remove deletes the entry outright",
        surface: "local",
        gate: "none",
        command: `rocketvault context remove staging
rocketvault context list`,
        expected:
          "staging is gone. Had it been current, `current` now reports local mode.",
        assert: "A removed context cannot be left dangling as current",
        why: '`context remove` deletes the saved context outright, unlike `context unset` which only clears the pointer. If the removed context happened to be the active one, its current-pointer is cleared too, as a side effect — so a removed context can never be left dangling as "current."',
        related: [{ id: "T13", rel: "contrasts" }],
        source:
          "VAULT_USER_ACCESS_JOURNEYS_v3.md § Journey T — `localhost` doesn't get you out of this",
      },
      {
        id: "T15",
        title: "An explicit --server always wins",
        surface: "cli",
        gate: "none",
        command: `rocketvault context use prod
rocketvault secrets list --server https://vault.staging.internal:8443`,
        expected: "Targets staging, not prod.",
        assert: "Precedence: --server, then ROCKETVAULT_ADDR, then the context",
        why: "`cliclient.ResolveTarget` checks, in order: the `--server` flag, then `ROCKETVAULT_ADDR`, then the active context. A context is the lowest-precedence source of a target, which is exactly why it is the one that causes surprises days after it was set rather than the one typed on the command line in front of you.",
        source:
          "VAULT_USER_ACCESS_JOURNEYS_v3.md § Journey T — Precedence, for when more than one of these is in play",
      },
      {
        id: "T16",
        title:
          "grant, list and revoke now work remotely, byte-identical to local",
        surface: "cli",
        gate: "none",
        precondition:
          "The prod context is active and authenticated as ops-oncall (see T6).",
        command: `rocketvault vault-access grant daeho --role "Key Vault Reader" --vault prod
rocketvault vault-access list --vault prod
rocketvault vault-access revoke <assignment-id> --vault prod`,
        expected: `granted Key Vault Reader to daeho in vault (assignment <assignment-id>)
ASSIGNMENT-ID                         ROLE                 PRINCIPAL-ID
<assignment-id>                       Key Vault Reader     <daeho-user-id>
revoked assignment <assignment-id>`,
        assert: "Same output as local mode — no separate remote formatter",
        why: "Local and remote print through the identical `Fprintf` format strings in `cmd/vault-access/{grant,list,revoke}.go` — there is no separate remote formatter, so the output for these three subcommands is byte-identical between local and remote mode.",
        source:
          "VAULT_USER_ACCESS_JOURNEYS_v3.md § Journey T — `vault-access` works remotely too",
      },
      {
        id: "T17",
        title:
          "A remote denial surfaces the same message as local for all three",
        surface: "cli",
        gate: "vault-role",
        precondition:
          "The prod context is active and authenticated as a principal with no role assignment in the vault.",
        command: `rocketvault vault-access grant daeho --role "Key Vault Reader" --vault prod`,
        expected: `Error: failed to grant a role: no role assignment in this vault grants the required action`,
        assert:
          "Same denial text locally and remotely, for grant, list and revoke",
        notes:
          "Substitute `list role assignments` or `revoke a role assignment` for the other two.",
        why: "`cliclient.CLIError` wraps whichever operation name the remote adapter passed (`grant a role`, `list role assignments`, `revoke a role assignment`), so the denial surfaces the same way for all three `vault-access` subcommands.",
        source:
          "VAULT_USER_ACCESS_JOURNEYS_v3.md § Journey T — `vault-access` works remotely too",
      },
      {
        id: "T18",
        title: "vault-access roles stays local-only regardless of context",
        surface: "cli",
        gate: "none",
        precondition: "The prod context is active.",
        command: `rocketvault vault-access roles`,
        expected:
          "Prints the compiled-in role list; the active prod context has no effect.",
        assert: "An active context, local or remote, has no effect on it",
        why: "`vault-access roles` did not join `remoteCapableCommands`. It is routed through `isLocalOnlyCommand` instead, because it only prints compiled-in role definitions and never contacts a server — so an active context, local or remote, has no effect on it either way.",
        source:
          "VAULT_USER_ACCESS_JOURNEYS_v3.md § Journey T — `vault-access` works remotely too",
      },
      {
        id: "T19",
        title:
          "ROCKETVAULT_VAULT diverges: vault-access honors it, secrets doesn't",
        surface: "cli",
        gate: "none",
        precondition:
          'The prod context is active (its default vault is "prod").',
        command: `export ROCKETVAULT_VAULT=payments

rocketvault vault-access list
rocketvault secrets list`,
        expected: `vault-access list acts on "payments" -- ResolveRemoteVault honors the env var.
secrets list acts on "prod" -- the secrets adapter never looks at ROCKETVAULT_VAULT and falls back to the context's default vault.`,
        assert: "Same shell, same context — two different vaults",
        flag: "trap",
        notes:
          "Neither command errors and neither prints which vault it resolved to — reproducible and quiet.",
        why: '`vault-access grant/list/revoke` are the only three callers of `cliclient.ResolveRemoteVault` (`internal/cliclient/vault.go`), whose precedence is `--vault` flag (only when actually typed) > `ROCKETVAULT_VAULT` > the context\'s default vault > config `vault` key > `"default"`. The `secrets` remote adapters (`cmd/secrets/list.go` and its siblings) never call that function — they resolve `--vault` then fall back straight to `target.Vault`, skipping `ROCKETVAULT_VAULT` entirely. This is a real divergence between command groups, not a documentation slip: it resolves only once plan 07 migrates the `secrets` remote adapters onto `ResolveRemoteVault` too.',
        source:
          "VAULT_USER_ACCESS_JOURNEYS_v3.md § Journey T — The `ROCKETVAULT_VAULT` divergence: `vault-access` reads it, `secrets` doesn't",
      },
      {
        id: "T20",
        title: "Only a --vault flag actually typed outranks ROCKETVAULT_VAULT",
        surface: "cli",
        gate: "none",
        precondition:
          "ROCKETVAULT_VAULT=payments exported, prod context active (see T19).",
        command: `rocketvault vault-access list --vault prod`,
        expected:
          'Acts on "prod" -- the flag was actually typed, so it outranks ROCKETVAULT_VAULT this time.',
        assert: "A typed flag wins; a non-empty default would not",
        flag: "trap",
        why: '`ResolveRemoteVault` checks `cmd.Flags().Changed("vault")`, not whether the flag\'s value is non-empty. A `--vault` left at a non-empty default is not a deliberate choice by the caller and does not outrank an exported `ROCKETVAULT_VAULT` — only a flag the caller actually typed does.',
        related: [{ id: "T19", rel: "depends" }],
        source:
          "VAULT_USER_ACCESS_JOURNEYS_v3.md § Journey T — The `ROCKETVAULT_VAULT` divergence: `vault-access` reads it, `secrets` doesn't",
      },
    ],
  },
  {
    key: "U",
    title: "Wiring (and not relying on) a vault webhook",
    actor: "Priya — admin, authorized by CanManageVault",
    premise:
      "The config is real: it creates, encrypts and stores a webhook with a genuine signing secret. Nothing in RocketVault ever calls it. Configuring it today buys you nothing operationally.",
    cases: [
      {
        id: "U1",
        title: "Set a webhook and capture the show-once signing secret",
        surface: "cli",
        gate: "management",
        command: `rocketvault vault-webhook set --vault prod --url https://hooks.example/rocketvault`,
        expected: `Webhook configured for vault "prod":
  URL: https://hooks.example/rocketvault
  Enabled: true

  Signing Secret: XfUHEYSqLFk4IhYKn4Ilr3Q9EGMQGLKCpZWPgjB948c

Store the signing secret now — it is not retrievable after this.`,
        assert: "The secret is printed exactly once",
      },
      {
        id: "U2",
        title: "get never emits the signing secret",
        surface: "cli",
        gate: "management",
        command: `rocketvault vault-webhook get --vault prod`,
        expected: `Webhook for vault "prod":
  URL: https://hooks.example/rocketvault
  Enabled: true
  Created: 2026-08-25T...
  Updated: 2026-08-25T...`,
        assert: "No Signing Secret field, on this call or any other",
        related: [{ id: "U1", rel: "depends" }],
      },
      {
        id: "U3",
        title: "Plain HTTP URLs are rejected at set time",
        surface: "cli",
        gate: "validation",
        command: `rocketvault vault-webhook set --vault prod --url http://hooks.example/rocketvault`,
        expected:
          'Error: set webhook failed: webhook url must be an absolute https URL: got scheme "http"',
        assert: "Rejected on the scheme",
      },
      {
        id: "U4",
        title: "Embedded credentials are rejected without echoing them back",
        surface: "cli",
        gate: "validation",
        command: `rocketvault vault-webhook set --vault prod --url https://user:pass@hooks.example/rocketvault`,
        expected: `Error: set webhook failed: webhook url must be an absolute https URL: must not embed
credentials (user:password@); authenticate the receiver with this vault's webhook
signing secret instead`,
        assert: "The credential is not echoed into terminal history or logs",
      },
      {
        id: "U5",
        title: "This is the vault-management tier, not a data-plane role",
        surface: "cli",
        gate: "management",
        precondition:
          "Run as sofia, holding crypto_manager globally and Key Vault Crypto Officer in prod.",
        command: `rocketvault vault-webhook set --vault prod --url https://hooks.example/rocketvault`,
        expected: `Error: permission denied: managing webhook config for vault "prod" requires admin or vaults/manage`,
        assert: "Denied — holding Administrator in the vault is not enough",
        why: "Webhook configuration is authorized by `CanManageVault`, the same vault-management tier as `vaults create/update/delete` — not a per-vault Azure data-plane role. Holding `Key Vault Administrator` or `Key Vault Crypto Officer` in the vault has no bearing on this check at all, which is why Sofia is denied despite holding Crypto Officer in `prod`.",
        source: "VAULT_USER_ACCESS_JOURNEYS_v3.md § Journey U",
      },
      {
        id: "U6",
        title: "The HTTP door gives the same answer",
        surface: "http",
        gate: "management",
        command: `curl -s -o /dev/null -w '%{http_code}\\n' -X PUT $BASE/vaults/prod/webhook \\
  -H "Authorization: Bearer $SOFIA_TOKEN" -H "Content-Type: application/json" \\
  -d '{"url":"https://hooks.example/rocketvault"}'`,
        expected: "403",
        assert: "No CLI/HTTP divergence here — both call CanManageVault",
        why: "`cmd/vault-webhook/authz.go`'s `requireCanManageVault` and `api/vault_webhook.go`'s `resolveAndAuthorizeVault` both call the identical `authz.CanManageVault` — there is no separate CLI-only bypass here the way there is for `vaults purge` (Journey K).",
        related: [{ id: "K3", rel: "contrasts" }],
        source: "VAULT_USER_ACCESS_JOURNEYS_v3.md § Journey U",
      },
      {
        id: "U7",
        title: "signing_secret appears only when one is minted",
        surface: "http",
        gate: "management",
        command: `curl -s -X PUT $BASE/vaults/prod/webhook \\
  -H "Authorization: Bearer $ADMIN_TOKEN" -H "Content-Type: application/json" \\
  -d '{"url":"https://hooks.example/rocketvault","rotate_secret":false}' | jq .`,
        expected: `{"url":"...", "enabled":true, "created_at":"...", "updated_at":"..."}`,
        assert: "No signing_secret field on an update that did not rotate one",
        verify: {
          look: "The JSON response has no `signing_secret` key at all — not `null`, not an empty string, absent entirely — because this update did not set `rotate_secret: true`.",
        },
        source: "VAULT_USER_ACCESS_JOURNEYS_v3.md § Journey U",
      },
      {
        id: "U8",
        title: "delete is idempotent on both surfaces",
        surface: "cli",
        gate: "management",
        command: `rocketvault vault-webhook delete --vault prod
rocketvault vault-webhook delete --vault prod`,
        expected: `webhook configuration deleted for vault "prod"
webhook configuration deleted for vault "prod"`,
        assert: "Same message twice, not an error",
        notes:
          "Contrast with `keys rotation-policy delete` (C20), which does error the second time.",
        related: [{ id: "C20", rel: "contrasts" }],
      },
      {
        id: "U9",
        title: "Nothing ever sends",
        surface: "http",
        gate: "none",
        command: `# Point the URL at a request bin and exercise every rotation,
# expiry and reminder path in this playbook.`,
        expected:
          "Zero inbound requests. There is no sender, dispatcher or delivery worker.",
        assert: "No outbound HTTP call is ever made",
        flag: "gap",
        notes:
          "**Do not build an operational process that depends on this webhook firing.**",
        why: "As of this writing, `rocketvault vault-webhook set/get/delete` creates, encrypts and stores a real webhook config with a real signing secret, but nothing in RocketVault ever makes an outbound HTTP call to it — there is no sender, dispatcher or delivery worker anywhere in the codebase. `docs/superpowers/specs/2026-08-20-webhook-delivery-primitive-design.md` proposes one but is status Proposed, not built. This is the same gap Journey C flags from the other side: a key rotation policy's `notify_before_expiry_days` is stored and echoed back, but nothing reads it, because there is nothing downstream — webhook or otherwise — that a trigger could call into yet.",
        source:
          "VAULT_USER_ACCESS_JOURNEYS_v3.md § Journey U — The config is real. Nothing sends.",
      },
    ],
  },
]
