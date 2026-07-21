#!/usr/bin/env bash
# Branch protection setup for Quantos-Labs/Quantos main branch.
#
# Usage: ./scripts/setup-branch-protection.sh
#
# Requires: gh (GitHub CLI) authenticated with admin scope.
# This script is idempotent — safe to re-run.

set -euo pipefail

REPO="Quantos-Labs/Quantos"
BRANCH="main"

echo "=== Setting up branch protection for $REPO:$BRANCH ==="

# Use the GitHub REST API to configure branch protection.
# Reference: https://docs.github.com/en/rest/branches/branch-protection

gh api "repos/$REPO/branches/$BRANCH/protection" \
  -X PUT \
  --input - <<'EOF'
{
  "required_status_checks": {
    "strict": true,
    "contexts": [
      "Format check",
      "Clippy lints",
      "Build (release)",
      "Tests",
      "Fuzz targets (build + 10s smoke)",
      "Security audit",
      "Foundry tests (Solidity)",
      "Docker reproducible build + hash",
      "Cargo reproducible build + hash"
    ]
  },
  "enforce_admins": true,
  "required_pull_request_reviews": {
    "required_approving_review_count": 2,
    "dismiss_stale_reviews": true,
    "require_code_owner_reviews": true,
    "require_last_push_approval": true
  },
  "restrictions": null,
  "required_linear_history": true,
  "allow_force_pushes": false,
  "allow_deletions": false,
  "block_creations": false,
  "required_signatures": true
}
EOF

echo ""
echo "=== Branch protection configured ==="
echo ""
echo "Rules enforced on $BRANCH:"
echo "  - No direct pushes (PR required)"
echo "  - 2 approving reviews required (incl. Code Owners)"
echo "  - Stale reviews auto-dismissed on new commits"
echo "  - Last push must be approved before merge"
echo "  - All CI status checks must pass"
echo "  - Branch must be up to date before merge"
echo "  - Linear history (no merge commits)"
echo "  - Signed commits required"
echo "  - Force pushes blocked"
echo "  - Branch deletion blocked"
echo "  - Rules enforced on admins too"
