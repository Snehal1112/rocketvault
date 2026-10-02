#!/bin/sh
# Renders /app/.rocketvault.yaml from the single template at
# /app/.rocketvault.docker.yaml.tmpl, substituting runtime secrets and
# driver-specific values from the container environment.
#
# RV_DB_DRIVER selects the database driver (default: sqlite3):
#
#   RV_DB_DRIVER=sqlite3   (default) -- used by Railway and plain
#                           "docker run". Requires only RV_MASTER_KEY and
#                           RV_BOOTSTRAP_TOKEN. Sets RV_DATABASE_DRIVER,
#                           RV_DATABASE_CONNECTION, and RV_LOG_FILE so the
#                           SQLite file and logs land under /app/data,
#                           which must be a mounted persistent volume.
#   RV_DB_DRIVER=postgres  -- used by docker-compose.yml and fly.toml,
#                           which both set it explicitly. Additionally
#                           requires POSTGRES_USER, POSTGRES_PASSWORD, and
#                           POSTGRES_DB.
#
# This exists because RocketVault's config loader (cmd/root.go initConfig,
# using viper) does not expand "${VAR}" placeholders inside YAML values, so
# secrets cannot reference environment variables directly. Rendering the file
# at startup keeps all secrets out of the image and out of version control,
# while letting the platform's own secret store (Railway variables, compose
# .env, Fly secrets) be the single source of truth.
#
# Optional env vars for both drivers:
#   RV_ISSUER, RV_CORS_ORIGINS -- public URL / CORS origin, default to
#                                  http://localhost:8774 in the template if
#                                  left unset (envsubst substitutes "").
#   RV_HSM_ENABLED              -- "true" initializes a SoftHSM2 software
#                                  token inside the container and sets
#                                  hsm.enabled: true in the rendered config.
#                                  Default: false (hsm.enabled: false, no
#                                  SoftHSM2 setup). This is a *software*
#                                  token, not a real hardware HSM -- it
#                                  unlocks RocketVault's HSM-only code paths
#                                  (OCT/AES keys, secp256k1 signing) but the
#                                  key material lives on the same mounted
#                                  volume as everything else, with no
#                                  hardware tamper-resistance. See
#                                  docs/hsm-softhsm2-testing.md.
#   RV_HSM_PIN                  -- PKCS#11 user PIN. Required when
#                                  RV_HSM_ENABLED=true (used both for the
#                                  SoftHSM2 token's PIN and, unless
#                                  RV_HSM_SO_PIN is set separately, its
#                                  SO-PIN too). Left empty otherwise.
#   RV_HSM_SO_PIN                -- SoftHSM2 token's Security Officer PIN
#                                  (only used to initialize/re-initialize the
#                                  token, never by RocketVault itself at
#                                  runtime). Defaults to RV_HSM_PIN if unset.
#   RV_TRUSTED_PROXIES          -- reverse proxies whose X-Forwarded-For may
#                                  be trusted, rendered into
#                                  server.trusted_proxies. Comma-separated,
#                                  each entry double-quoted, e.g.
#                                  '"10.0.0.0/8","172.16.0.0/12"'. Default:
#                                  empty, which renders [] (trust nothing).
#                                  Set it whenever a proxy sits in front of
#                                  the container (Fly, Railway, Caddy, nginx),
#                                  or every client shares one login
#                                  rate-limit bucket.
set -eu

RV_DB_DRIVER="${RV_DB_DRIVER:-sqlite3}"
RV_HSM_ENABLED="${RV_HSM_ENABLED:-false}"
TEMPLATE="/app/.rocketvault.docker.yaml.tmpl"
RENDERED="/app/.rocketvault.yaml"

: "${RV_MASTER_KEY:?RV_MASTER_KEY is required — generate with: openssl rand -base64 32}"
: "${RV_BOOTSTRAP_TOKEN:?RV_BOOTSTRAP_TOKEN is required — generate with: openssl rand -base64 32}"
: "${RV_HSM_PIN:=}"
: "${RV_TRUSTED_PROXIES:=}"
export RV_TRUSTED_PROXIES

case "$RV_DB_DRIVER" in
    sqlite3)
        # A platform volume (Railway, Fly) mounts over /app/data with
        # root:root ownership, undoing the image's build-time chown. Fix it
        # up before mkdir -- this script still runs as root at this point.
        chown rocketvault:rocketvault /app/data
        mkdir -p /app/data/logs
        chown rocketvault:rocketvault /app/data/logs
        RV_DATABASE_DRIVER="sqlite3"
        RV_DATABASE_CONNECTION="/app/data/rocketvault.db"
        RV_LOG_FILE="/app/data/logs/rocketvault.log"
        ;;
    postgres)
        : "${POSTGRES_USER:?POSTGRES_USER is required}"
        : "${POSTGRES_PASSWORD:?POSTGRES_PASSWORD is required}"
        : "${POSTGRES_DB:?POSTGRES_DB is required}"
        # Same as the sqlite3 branch: docker-compose.yml's rocketvault_logs
        # volume mounts over /app/logs with root:root ownership.
        chown rocketvault:rocketvault /app/logs
        RV_DATABASE_DRIVER="postgres"
        RV_DATABASE_CONNECTION="postgres://${POSTGRES_USER}:${POSTGRES_PASSWORD}@postgres:5432/${POSTGRES_DB}?sslmode=disable"
        RV_LOG_FILE="./logs/rocketvault.log"
        ;;
    *)
        echo "docker-entrypoint.sh: unknown RV_DB_DRIVER '$RV_DB_DRIVER' (expected sqlite3 or postgres)" >&2
        exit 1
        ;;
esac
export RV_DATABASE_DRIVER RV_DATABASE_CONNECTION RV_LOG_FILE

# SoftHSM2 setup. Independent of RV_DB_DRIVER -- runs after the case above so
# /app/data already exists (sqlite3 branch) or is created here (postgres
# branch never otherwise touches /app/data).
if [ "$RV_HSM_ENABLED" = "true" ]; then
    : "${RV_HSM_PIN:?RV_HSM_PIN is required when RV_HSM_ENABLED=true}"
    RV_HSM_SO_PIN="${RV_HSM_SO_PIN:-$RV_HSM_PIN}"

    mkdir -p /app/data/softhsm/tokens
    chown -R rocketvault:rocketvault /app/data/softhsm

    # SOFTHSM2_CONF itself is a fixed Dockerfile ENV (not exported here), so
    # a later "docker exec"/"railway ssh" CLI command finds it too -- see the
    # Dockerfile's own comment on that ENV line.
    if [ ! -f "$SOFTHSM2_CONF" ]; then
        cat > "$SOFTHSM2_CONF" <<EOF
directories.tokendir = /app/data/softhsm/tokens/
objectstore.backend = file
log.level = INFO
EOF
        chown rocketvault:rocketvault "$SOFTHSM2_CONF"
    fi

    # --init-token wipes any existing token under the same label, so only run
    # it once -- on every later boot the token already exists on the mounted
    # volume. --free lets SoftHSM2 pick the slot; RocketVault's hsm.slot_id: 0
    # in the template means "match by token_label", not "slot 0", so the
    # actual slot number SoftHSM2 assigns (it reassigns on every init) does
    # not matter.
    if ! gosu rocketvault softhsm2-util --show-slots 2>/dev/null | grep -q "rocketvault"; then
        gosu rocketvault softhsm2-util --init-token --free --label rocketvault \
            --so-pin "$RV_HSM_SO_PIN" --pin "$RV_HSM_PIN"
    fi
fi
export RV_HSM_ENABLED

envsubst '${RV_MASTER_KEY} ${RV_BOOTSTRAP_TOKEN} ${RV_CORS_ORIGINS} ${RV_ISSUER} ${RV_HSM_PIN} ${RV_HSM_ENABLED} ${RV_DATABASE_DRIVER} ${RV_DATABASE_CONNECTION} ${RV_LOG_FILE} ${RV_TRUSTED_PROXIES}' \
    < "$TEMPLATE" > "$RENDERED"
chown rocketvault:rocketvault "$RENDERED"

# Drop from root (needed above to fix volume-mount ownership) to the
# unprivileged rocketvault user before running the actual server process.
exec gosu rocketvault "$@"
