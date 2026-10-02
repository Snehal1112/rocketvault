# Deploying RocketVault to Railway

`railway.json` in the repo root controls the build and deploy settings Railway reads on
every deployment (builder, health check, restart policy). It cannot declare volumes,
variables, or replica counts — those are project-level resources set through the CLI or
dashboard, covered below.

## 1. Install the CLI and create the project

```bash
railway login
railway init   # from the repo root; builds from the committed Dockerfile
```

## 2. Attach a persistent volume

RocketVault's SQLite database file — which also holds the JWT signing key
(`jwt.key_source: self_pki`) and logs — lives under `/app/data`. Without a volume there,
a redeploy loses the database, invalidates every session, and drops all logs.

```bash
railway volume add --mount-path /app/data -s <service-name>
```

Dashboard alternative: select the service → **Volumes** → **New Volume**, mount path
`/app/data`.

## 3. Set the required environment variables

Both must be base64-encoded random values:

```bash
railway variable set RV_MASTER_KEY="$(openssl rand -base64 32)" -s <service-name>
railway variable set RV_BOOTSTRAP_TOKEN="$(openssl rand -base64 32)" -s <service-name>
```

Optional — default to `http://localhost:8774` if unset; set these once Railway assigns a
domain:

```bash
railway variable set RV_ISSUER="https://<your-app>.up.railway.app" -s <service-name>
railway variable set RV_CORS_ORIGINS="https://<your-app>.up.railway.app" -s <service-name>
```

`RV_DB_DRIVER` defaults to `sqlite3` in `docker-entrypoint.sh`, so it does not need to be
set. Set it explicitly only if you want that intent visible in the dashboard:

```bash
railway variable set RV_DB_DRIVER=sqlite3 -s <service-name>
```

`RV_HSM_PIN` is left unset — HSM is off by default.

Railway's edge proxy sits in front of the service, so set `RV_TRUSTED_PROXIES` to the
address ranges that proxy connects from. Take the ranges from Railway's own documentation;
this guide does not list them. The value is rendered into `server.trusted_proxies`:
comma-separated IPs or CIDR ranges, each one double-quoted:

```bash
railway variable set RV_TRUSTED_PROXIES='"<range-1>","<range-2>"' -s <service-name>
```

Unset, it renders `[]`: the forwarded headers are ignored, every client shares the proxy's
address, and one client can throttle every login. The proxy must append to or overwrite
`X-Forwarded-For`.

## Optional: SoftHSM (software HSM)

SoftHSM2 is a software token that implements PKCS#11, letting you test the HSM code path without hardware — note: key material lives on disk with no hardware tamper-resistance.

To enable SoftHSM2 in your Railway deployment:

```bash
railway variable set RV_HSM_ENABLED=true -s <service-name>
railway variable set RV_HSM_PIN="<your-pin>" -s <service-name>
railway variable set RV_HSM_SO_PIN="<your-so-pin>" -s <service-name>
```

- `RV_HSM_ENABLED`: Set to `true` to initialize the token on container start and enable `hsm.enabled: true` in the config. Default: `false`.
- `RV_HSM_PIN`: User PIN for PKCS#11 operations (any value you choose).
- `RV_HSM_SO_PIN`: Security Officer PIN used only at token initialization. Defaults to `RV_HSM_PIN` if unset.

Token data persists at `/app/data/softhsm/tokens/` on your persistent volume, just like the SQLite DB.

See [HSM / PKCS#11 with SoftHSM2](./hsm-softhsm2-testing.md) for manual local setup and testing procedures.

## 4. Deploy

```bash
railway up
```

## 5. Create the first admin

`railway ssh -- <cmd>` runs a one-off command inside the deployed container and exits,
unlike a bare `railway ssh`, which opens an interactive shell:

```bash
railway ssh -s <service-name> -- \
  /app/rocketvault users admin --admin-username=admin --admin-password=<pw> --bootstrap-token=<RV_BOOTSTRAP_TOKEN>
```

## Single instance only

RocketVault is a single-vault system: multiple replicas would race on schema migrations
at startup. Scale vertically, not horizontally. Do not raise the replica count from the
dashboard's Scaling settings — `railway.json` has no replica field, and none should be
added.

RocketVault serves on `:8774`. Railway terminates TLS at its edge proxy and forwards HTTP
to the container port Railway auto-detects from the Dockerfile's `EXPOSE`.
