#!/bin/bash
# Push quantos node changes to both quantos-audit and quantos-test
set -e

MSG=${1:-"chore: sync"}

git add -A
git commit -m "$MSG" || echo "(nothing new to commit)"

git push origin main
git push quantos-test main

echo ""
echo "✓ pushed to quantos-audit (origin)"
echo "✓ pushed to quantos-test"
