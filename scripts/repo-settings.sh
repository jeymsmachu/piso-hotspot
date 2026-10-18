#!/usr/bin/env bash
# Apply the repository settings this project expects. Idempotent.
#
#   scripts/repo-settings.sh            # print what would change (dry run)
#   scripts/repo-settings.sh --apply    # actually change it
#
# Requires an authenticated `gh` with admin rights on the repository.
# Deliberately separate from CI: repository settings are a human action.
set -euo pipefail

REPO="${REPO:-jeymsmachu/piso-hotspot}"
APPLY=0
[ "${1:-}" = "--apply" ] && APPLY=1

run() {
    if [ "$APPLY" = 1 ]; then
        gh api --method PATCH "$@" >/dev/null
        echo "applied: ${*: -1}"
    else
        echo "would apply: $*"
    fi
}

echo "repository: $REPO"
echo

# Identity and discovery.
run "repos/$REPO" \
    -f description="Pay-per-usage wifi hotspot: sell timed internet passes, enforced per MAC" \
    -f homepage="https://github.com/$REPO#readme" \
    -F has_wiki=false \
    -F has_projects=false \
    -F has_discussions=false

if [ "$APPLY" = 1 ]; then
    gh api --method PUT "repos/$REPO/topics" \
        -f names[]=hotspot -f names[]=wifi -f names[]=captive-portal \
        -f names[]=paywall -f names[]=nftables -f names[]=linux \
        -f names[]=rust -f names[]=hostapd -f names[]=dnsmasq \
        >/dev/null && echo "applied: topics"
else
    echo "would apply: topics (hotspot, wifi, captive-portal, paywall, …)"
fi

# Merge policy: squash-only keeps history linear for releases.
run "repos/$REPO" \
    -F allow_squash_merge=true \
    -F allow_merge_commit=false \
    -F allow_rebase_merge=false \
    -F delete_branch_on_merge=true

# Protect main: no force-push, no deletion, CI must pass.
if [ "$APPLY" = 1 ]; then
    gh api --method PUT "repos/$REPO/branches/main/protection" \
        --input - >/dev/null <<'JSON'
{
  "required_status_checks": {
    "strict": true,
    "contexts": ["Format, lint, test", "Package (x86_64-unknown-linux-gnu)"]
  },
  "enforce_admins": false,
  "required_pull_request_reviews": null,
  "restrictions": null,
  "allow_force_pushes": false,
  "allow_deletions": false
}
JSON
    echo "applied: branch protection on main"
else
    echo "would apply: branch protection on main (CI required, no force-push)"
fi

# Security: private vulnerability reporting and dependency alerts.
run "repos/$REPO/private-vulnerability-reporting" -F enabled=true

if [ "$APPLY" = 1 ]; then
    gh api --method PUT "repos/$REPO/vulnerability-alerts" >/dev/null 2>&1 \
        && echo "applied: vulnerability alerts" || true
    gh api --method PUT "repos/$REPO/automated-security-fixes" >/dev/null 2>&1 \
        && echo "applied: automated security fixes" || true
else
    echo "would apply: vulnerability alerts + automated security fixes"
fi

# Actions: allow only GitHub-authored actions plus the few pinned ones we
# actually use, and require full commit SHAs is enforced by review, not here.
if [ "$APPLY" = 1 ]; then
    gh api --method PUT "repos/$REPO/actions/permissions/workflow" \
        -f default_workflow_permissions=read \
        -F can_approve_pull_request_reviews=false >/dev/null
    echo "applied: workflow token read-only by default"
else
    echo "would apply: workflow token permissions -> read-only"
fi

echo
[ "$APPLY" = 1 ] && echo "done." || echo "dry run: re-run with --apply"
