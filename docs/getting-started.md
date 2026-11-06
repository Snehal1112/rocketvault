# Getting Started with RocketVault

RocketVault is a self-hosted vault for secrets, keys, and certificates. Pick the path that matches what you're trying to do.

| If you want to… | Use this way |
|---|---|
| Script vault administration from a terminal | [1. CLI (human-driven)](usage-guide.md#1-cli-human-driven) |
| Call RocketVault from my own application code or CI/CD pipeline | [2. REST API (programmatic)](usage-guide.md#2-rest-api-programmatic) |
| Let another service fetch secrets without a human logging in | [3. OAuth2 / Service Accounts (machine-to-machine)](usage-guide.md#3-oauth2--service-accounts-machine-to-machine) |
| Have my Go app pull a secret at startup | [4. Vault Client library (embedded secret consumption)](usage-guide.md#4-vault-client-library-embedded-secret-consumption) |
| Let a third party verify my JWTs without calling back to RocketVault | [5. JWKS endpoint (token verification by external services)](usage-guide.md#5-jwks-endpoint-token-verification-by-external-services) |
| Back up my vault before an upgrade or disaster-recover from a backup | [6. Backup / restore tooling](usage-guide.md#6-backup--restore-tooling) |
| Wire vault health into my monitoring or orchestration stack | [7. Health / monitoring integration](usage-guide.md#7-health--monitoring-integration) |
| Use a hardware security module so private keys never touch my server's memory | [8. HSM-backed mode (PKCS#11)](usage-guide.md#8-hsm-backed-mode-pkcs11) |
| Decide how to deploy RocketVault (standalone, Docker, cloud) | [9. Deployment modes](usage-guide.md#9-deployment-modes) |

## Local setup

Prerequisites:

- Go 1.25 or later, with CGO enabled (the SQLite driver needs it).
- SQLite for development. PostgreSQL is optional and recommended for production.
- SoftHSM2 only if you want to try HSM-backed keys. See [HSM with SoftHSM2](hsm-softhsm2-testing.md).

Create your local config once per clone:

```bash
cp .rocketvault.yaml.example .rocketvault.yaml
openssl rand -base64 32   # run twice: one value for master_key, one for bootstrap_token
```

Replace both `GENERATE_WITH` placeholders in `.rocketvault.yaml` with those values. Never commit
`.rocketvault.yaml`; it is already in `.gitignore`. Then start the server and create the first admin:

```bash
go run main.go serve
./rocketvault users admin --admin-username=admin --admin-password=<password> --bootstrap-token=<bootstrap_token>
```

The first admin setup, including TOTP enrollment, is covered in the [admin setup guide](admin-setup.md).
More config notes are in [configuration](contributing/configuration.md).

## Choose how you use it

Each section in the usage guide includes a "When to use it", worked examples, prerequisites, and gotchas that bite in practice. Start with the row that matches your goal, then dive into the deep-dive link at the end of that section if you need more detail.
