#!/usr/bin/env bash
# Creates a signed release tag (major, minor, or patch bump) and pushes it.
# Usage: ./release.sh [major|minor|patch]

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

usage() {
    echo "Usage: $0 [major|minor|patch|<version>]"
    echo ""
    echo "  major     v1.2.3 -> v2.0.0"
    echo "  minor     v1.2.3 -> v1.3.0"
    echo "  patch     v1.2.3 -> v1.2.4"
    echo "  <version> explicit target, e.g. v4.0.0 or 4.0.0 -- use this when the"
    echo "            next release isn't a relative bump from the latest tag"
    exit 1
}

# Working tree must be clean before we tag -- a signed release tag should
# capture exactly what's on origin, not local uncommitted state.
if [[ -n "$(git status --porcelain)" ]]; then
    echo -e "${RED}Working tree has uncommitted changes. Commit or stash before releasing.${NC}"
    git status --short
    exit 1
fi

# Guard against the H4 regression (docs/known-bugs.md § B10): a real
# .rocketvault.yaml (or a dash/dot-separated sibling) must never be
# git-tracked. Mirrors the "No tracked RocketVault config files" check in
# .github/workflows/go.yml so a bad state is caught before tagging, not
# after push.
if git ls-files | grep -E '^\.rocketvault([.-].*)?\.yaml$|^\.rocketvault\.yaml\.local$'; then
    echo -e "${RED}A real RocketVault config file is tracked in git — see docs/known-bugs.md § B10${NC}"
    exit 1
fi

# Resolve bump type from argument or prompt.
bump="${1:-}"
if [[ -z "$bump" ]]; then
    echo -e "${BLUE}Bump type:${NC} major / minor / patch, or an explicit version (e.g. v4.0.0)"
    read -rp "> " bump
fi

# Find the latest semver tag.
latest=$(git tag --list "v*" | grep -E '^v[0-9]+\.[0-9]+\.[0-9]+$' | sort -V | tail -1 || true)
if [[ -z "$latest" ]]; then
    latest="v0.0.0"
fi

if [[ "$bump" =~ ^v?[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    # Explicit target version. Needed because the next release isn't always
    # a relative bump from the latest tag -- e.g. this branch (v-4.0.0)
    # jumps straight from v0.2.3 to v4.0.0, which "major" alone can't reach.
    new_tag="v${bump#v}"
else
    case "$bump" in
        major|minor|patch) ;;
        *) echo -e "${RED}Invalid bump type or version: ${bump}${NC}"; usage ;;
    esac

    # Strip leading 'v' and split.
    version="${latest#v}"
    major="${version%%.*}"; rest="${version#*.}"
    minor="${rest%%.*}"; patch="${rest#*.}"

    # Bump.
    case "$bump" in
        major) major=$((major + 1)); minor=0; patch=0 ;;
        minor) minor=$((minor + 1)); patch=0 ;;
        patch) patch=$((patch + 1)) ;;
    esac

    new_tag="v${major}.${minor}.${patch}"
fi

if git tag --list "$new_tag" | grep -qx "$new_tag"; then
    echo -e "${RED}Tag ${new_tag} already exists.${NC}"
    exit 1
fi

echo ""
echo -e "  Current tag : ${YELLOW}${latest}${NC}"
echo -e "  New tag     : ${GREEN}${new_tag}${NC}"
echo ""
read -rp "Create and push signed tag ${new_tag}? [y/N] " confirm
if [[ "${confirm,,}" != "y" ]]; then
    echo "Aborted."
    exit 0
fi

# Verify GPG signing is configured.
signing_key=$(git config --get user.signingkey 2>/dev/null || true)
if [[ -z "$signing_key" ]]; then
    echo -e "${RED}No user.signingkey configured. Run:${NC}"
    echo "  git config user.signingkey <KEY_ID>"
    exit 1
fi

# Create signed tag.
git tag -s "$new_tag" -m "Release ${new_tag}"

# Verify before pushing.
if ! git tag -v "$new_tag" 2>&1 | grep -q "Good signature"; then
    echo -e "${RED}Tag signature verification failed. Not pushing.${NC}"
    git tag -d "$new_tag"
    exit 1
fi

git push origin "$new_tag"

echo ""
echo -e "${GREEN}Tagged and pushed: ${new_tag}${NC}"
echo "GitHub Actions release workflow will start shortly."
echo "Monitor: https://github.com/$(git remote get-url origin | sed 's/.*github.com[:/]\(.*\)\.git/\1/')/actions"
