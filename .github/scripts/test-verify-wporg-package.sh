#!/usr/bin/env bash
#
# Self-test for verify-wporg-package.sh: proves the check actually rejects a
# forbidden path/identifier, not just that it passes on already-clean input
# (a verifier that always exits 0 would "pass" that trivially). Builds a
# throwaway copy of the current includes/ tree, confirms it passes clean,
# deliberately inserts one forbidden file, confirms rejection, removes it,
# confirms it passes again -- then a fresh, unmodified copy is what
# release-package.yml and wporg-deploy.yml actually verify, this script
# only proves the checker itself works.
#
# Usage: test-verify-wporg-package.sh (no arguments; run from the repo root)

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
VERIFIER="${REPO_ROOT}/.github/scripts/verify-wporg-package.sh"
WORKDIR="$(mktemp -d)"
trap 'rm -rf "${WORKDIR}"' EXIT

mkdir -p "${WORKDIR}/includes"
cp -r "${REPO_ROOT}/includes/." "${WORKDIR}/includes/"
rm -rf "${WORKDIR}/includes/extensions"
rm -f "${WORKDIR}/includes/modules/class-github-update-checker.php"

echo "── Baseline: clean copy must pass ──────────────────────────────────"
if ! bash "${VERIFIER}" "${WORKDIR}"; then
  echo "FAIL: verifier rejected a clean copy -- false positive." >&2
  exit 1
fi

echo "── Negative control: inserting a forbidden identifier ──────────────"
mkdir -p "${WORKDIR}/includes/extensions"
cat > "${WORKDIR}/includes/extensions/planted-violation.php" <<'PHP'
<?php
// Deliberately planted by test-verify-wporg-package.sh -- if you are
// reading this in a real build, the negative-control test itself is
// broken (this file should never survive past the test that creates it).
const PLANTED_FULLY_AUTOMATIC_MARKER = 'fully_automatic';
PHP

if bash "${VERIFIER}" "${WORKDIR}" > /dev/null 2>&1; then
  echo "FAIL: verifier passed a copy with a planted violation -- false negative." >&2
  exit 1
fi
echo "Confirmed: verifier correctly rejected the planted violation."

echo "── Cleanup: removing the planted violation ──────────────────────────"
rm -f "${WORKDIR}/includes/extensions/planted-violation.php"
rmdir "${WORKDIR}/includes/extensions" 2>/dev/null || true

echo "── Post-cleanup: must pass again ────────────────────────────────────"
if ! bash "${VERIFIER}" "${WORKDIR}"; then
  echo "FAIL: verifier still rejected after the planted violation was removed." >&2
  exit 1
fi

echo "verify-wporg-package.sh self-test passed: correctly rejects a real violation and correctly passes clean input, both before and after."
