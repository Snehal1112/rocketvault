# Key Export — Decision Record

**Date**: 2026-08-25
**Status**: Superseded for software keys (2026-10-01) — HSM keys stay non-extractable
**Scope**: `.claude/azure-keyvault-parity.md` (documentation amendment only — no code paths touched)
**Branch target**: v-4.0.0
**Source finding**: gap-audit review of the secrets/keys/certificates import-export
asymmetry; see the existing row in `.claude/azure-keyvault-parity.md` §2
("EXPORT blocked (keys non-extractable)", line 51) and
`internal/crypto/pkcs11_provider.go:153,222,260`

---

This is a decision record, not an implementation design — it documents a considered
"no," and instructs a documentation fix, not a code change. It is filed alongside
[2026-08-25-key-import-jwk-design.md](2026-08-25-key-import-jwk-design.md) because
the two questions ("should keys be importable?" / "should keys be exportable?") were
raised together but resolve in opposite directions.

## Question

Should RocketVault add a key-export capability — an operation that returns a key's
private material (plaintext PEM or JWK) to the caller for use outside the vault?

This is not "RocketVault is missing key export." Azure Key Vault keys are
non-extractable by design: once a key exists in a vault, its private material never
leaves it. RocketVault's own parity doc already tracks this as intentional:

> `EXPORT blocked (keys non-extractable) | ✅ | ✅ buildKeyResponse emits only JWK
> public components (crypto.ExtractPublicComponents) and model.KeyVersion omits
> Value; the one response carrying stored material is the backup blob, and that is
> the master-key AES-256-GCM ciphertext (common.EncryptSecret) or a bare pkcs11:
> handle — never plaintext PEM | ✅`
> — `.claude/azure-keyvault-parity.md:51`

The question this record answers is narrower and more concrete: does that hold for
**every** key backend RocketVault supports, or only the one where it's structurally
forced?

## Analysis

RocketVault's `crypto.KeyProvider` interface (`internal/crypto/provider.go:10-41`)
has two implementations, and the non-extractability guarantee rests on different
foundations in each:

### 1. HSM-backed keys (`PKCS11KeyProvider`) — a hard technical wall

Every key object the PKCS#11 provider creates is generated with
`CKA_EXTRACTABLE: false`:

```go
// internal/crypto/pkcs11_provider.go:153 (RSA private key attrs)
p11.NewAttribute(p11.CKA_EXTRACTABLE, false),

// internal/crypto/pkcs11_provider.go:222 (ECDSA private key attrs)
p11.NewAttribute(p11.CKA_EXTRACTABLE, false),

// internal/crypto/pkcs11_provider.go:260 (AES secret key attrs)
p11.NewAttribute(p11.CKA_EXTRACTABLE, false),
```

This is enforced by the PKCS#11 token itself, not by RocketVault's application
logic. There is no code path — today or after any conceivable future change — that
could extract this material, short of a hardware-level compromise of the token.
Export is not a missing feature here; it's asking the token to do something it is
built to refuse.

### 2. Software-backed keys (`SoftwareKeyProvider`) — a product decision, not a wall

Software keys are stored differently: the provider's `Generate*Key` handle is a PEM
string, which the service layer encrypts with `common.EncryptSecret` (master-key
AES-256-GCM, **reversible**) before writing it to `keys.value`
(`internal/services/keys/key_service.go:255-263`, mirrored for ECDSA at
`:347-355`). Nothing about this encryption is one-way. `common.DecryptSecret` could
recover the plaintext PEM today — `GetPublicJWK`
(`internal/services/keys/key_service.go:556-601`) already performs exactly this
decrypt step to extract *public* components; extracting the private key instead
would be a small code change, not a new capability.

So for software-backed keys, "keys can't be exported" is a decision RocketVault has
made, not a wall it's run into. That distinction matters, because it means the
question is genuinely open and deserves a stated reason — which is what this record
provides.

**The reason**: Azure Key Vault presents one non-extractability contract to callers,
regardless of which backing tier (Standard/Premium/Managed HSM) a vault runs on.
RocketVault's stated goal throughout `.claude/azure-keyvault-parity.md` is
API/behavioral parity with Azure. Adding export only for the software backend would
create a security-relevant behavior that is:

- **Invisible to the caller.** `GetKey`/`ListKeys` responses don't reveal which
  backend stores a given key. A client application built against "keys never leave
  the vault" would silently stop being true the moment an operator switches a
  deployment from HSM-backed to software-backed, with no API signal that the trust
  model changed.
- **A deployment-configuration decision masquerading as a per-key one.** Whether a
  key is exportable would depend on infrastructure choice (is HSM configured?), not
  on anything the key's owner explicitly opted into when creating it.

### Decision

| Option | Verdict | Reason |
|---|---|---|
| No export capability (status quo) | **Chosen** | Matches Azure Key Vault's non-extractability contract on both key backends; avoids a silent, deployment-dependent security divergence |
| Export for software-backed keys only | Rejected | Diverges from Azure parity; creates an invisible trust-model difference between HSM and software vaults that the API gives callers no way to detect |
| Export for both backends | Rejected | Impossible for HSM-backed keys (`CKA_EXTRACTABLE: false` is enforced by the token); would require a backend-specific carve-out, which is the same objection as the row above |

RocketVault will not add a key-export capability, for either backend, now or as a
planned feature. This closes the question rather than leaving it open as an
unstated gap.

## Non-goals

This record does not reopen `POST /keys/{id}/backup`
(`.claude/azure-keyvault-parity.md:47`, already ✅). Backup/restore is a distinct,
same-instance disaster-recovery mechanism: its blob carries the same
`common.EncryptSecret` ciphertext or `pkcs11:` handle the database stores, useful
only to a RocketVault instance holding the same master key (or the same HSM
token/slot for HSM keys). It does not return usable plaintext key material to a
human or to a different system, so it does not satisfy — and was never meant to
satisfy — what "key export" means in this record.

## Documentation

1. Amend the existing row at `.claude/azure-keyvault-parity.md:51`
   ("EXPORT blocked (keys non-extractable)") to add the software-key nuance from
   Analysis §2 above — the row's current justification only argues from the
   HSM/JWK-response angle; it should also state plainly that software-backed keys
   are *technically* extractable via `common.DecryptSecret` and export is excluded
   by product decision, not technical necessity, for the parity reasons stated
   above.
2. Add a dated footnote cross-reference from that row to this decision record,
   matching the file's existing footnote convention (e.g. the
   "*Re-verified 2026-08-19 against ...*" style used elsewhere in
   `.claude/azure-keyvault-parity.md`).
3. Do **not** add a `.claude/known-bugs.md` entry. This is confirmed-intentional
   behavior, not a defect — a known-bugs entry would misrepresent it.
4. No `.claude/roadmap-azure-parity-and-beyond.md` or `README.md` roadmap change is
   needed: key export was never listed as planned work in either document, so there
   is nothing to close.

## Amendment (2026-10-01): superseded for software keys

[2026-10-01-certificate-and-key-export-design.md](2026-10-01-certificate-and-key-export-design.md)
adds `POST /keys/{key_id}/export` for software-backed keys. This record's
reasoning was that software-key export would be an invisible,
deployment-dependent change to the "keys never leave the vault" trust model.
The amendment answers that directly: exportability is an explicit, immutable,
per-key `exportable` flag, set only by the key's creator at creation or import,
visible in `GET key`, and false for every key that existed before the change.
Export further requires the narrow Key Vault Key Exporter role (which only a
global admin can grant) or Administrator (which a delegated Data Access
Administrator can also grant), and every attempt is audited.

What does not change: HSM-backed keys remain non-extractable
(`CKA_EXTRACTABLE: false`) and `ExportKey` refuses every `pkcs11:` key; `oct`
and ES256K keys are refused too. A key created without `exportable: true` can
never be exported.
