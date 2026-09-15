#!/usr/bin/env bash
# Deploys to Railway and blocks until the deployment reaches a terminal
# state. `railway up --ci` alone only streams build logs and exits -- it
# does not reliably confirm the deployment actually went healthy, so CI
# must poll `railway deployment list` for a terminal status before it can
# call the release a success.
#
# Usage: pass railway CLI `up`-compatible args, e.g.:
#   railway-deploy-and-wait.sh [PATH] [--path-as-root] --service NAME --environment ENV -m "message"
#
# Requires RAILWAY_TOKEN in the environment and `jq` on PATH.
set -euo pipefail

service=""
environment=""
args=("$@")

i=0
while [[ $i -lt ${#args[@]} ]]; do
  case "${args[$i]}" in
    --service) service="${args[$((i + 1))]:-}" ;;
    --environment) environment="${args[$((i + 1))]:-}" ;;
  esac
  i=$((i + 1))
done

if [[ -z "$service" || -z "$environment" ]]; then
  echo "railway-deploy-and-wait.sh: --service and --environment are required" >&2
  exit 1
fi

upload=$(railway up "${args[@]}" --detach --json)
echo "$upload"

deployment_id=$(echo "$upload" | jq -r '.deploymentId // empty')
if [[ -z "$deployment_id" ]]; then
  echo "railway-deploy-and-wait.sh: no deploymentId in upload response" >&2
  exit 1
fi

echo "Waiting for deployment ${deployment_id} (service=${service}, environment=${environment}) to reach a terminal state..."

# A cold Dockerfile build (e.g. the Go/CGO backend with no warm layer cache)
# has been observed to spend 10+ minutes in BUILDING before the healthcheck
# even starts, so this needs real headroom, not just enough for a quick
# Railpack static build. interval=15s * attempts=160 = 40 minutes.
interval=15
attempts=160
last_status=""
for ((i = 1; i <= attempts; i++)); do
  status=$(railway deployment list --service "$service" --environment "$environment" --json \
    | jq -r --arg id "$deployment_id" '.[] | select(.id == $id) | .status // empty')
  status="${status:-unknown}"

  # Only log on a status change or every ~5 minutes, so a long BUILDING
  # phase doesn't spam hundreds of identical lines into the CI log.
  if [[ "$status" != "$last_status" || $((i % 20)) -eq 0 ]]; then
    elapsed=$((i * interval))
    echo "[${elapsed}s elapsed] status: ${status}"
    last_status="$status"
  fi

  case "$status" in
    SUCCESS)
      echo "Deployment succeeded."
      exit 0
      ;;
    FAILED | CRASHED | REMOVED | REMOVING)
      echo "Deployment ended in state: ${status}" >&2
      exit 1
      ;;
  esac

  sleep "$interval"
done

echo "Timed out after $((attempts * interval))s waiting for deployment ${deployment_id} to finish" >&2
exit 1
