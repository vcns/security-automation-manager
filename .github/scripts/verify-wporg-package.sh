#!/usr/bin/env bash
#
# Verifies a WordPress.org-channel plugin directory contains none of the
# paths or identifiers tied to a paid automation mode or the GitHub-channel
# updater. Used identically by both paths that can produce a WordPress.org-
# bound package:
#   - release-package.yml, against the built dist/wporg/... tree
#   - wporg-deploy.yml, against the raw tagged checkout (after its own
#     removal step, mirroring release-package.yml's)
# so both enforce the exact same rules from one place, rather than two
# grep patterns that could silently drift apart.
#
# Usage: verify-wporg-package.sh <path-to-plugin-root>

set -euo pipefail

if [ "$#" -ne 1 ]; then
  echo "Usage: $0 <path-to-plugin-root>" >&2
  exit 2
fi

TARGET="$1"

if [ ! -d "${TARGET}" ]; then
  echo "Not a directory: ${TARGET}" >&2
  exit 2
fi

FAILED=0

# ── Forbidden paths ──────────────────────────────────────────────────────────
# Directories/files that must be physically absent, not merely inert.
FORBIDDEN_PATHS=(
  "includes/extensions"
  "includes/modules/class-github-update-checker.php"
  "includes/build-channel.php"
  "offline"
)

for path in "${FORBIDDEN_PATHS[@]}"; do
  if [ -e "${TARGET}/${path}" ]; then
    echo "FORBIDDEN PATH present: ${path}" >&2
    FAILED=1
  fi
done

# ── Forbidden identifiers ────────────────────────────────────────────────────
# Every string tied specifically to a paid automation mode's identifier,
# entitlement check, settings, or checkout mechanism. Deliberately does NOT
# include the generic wp_sam_register_automation_modes/wp_sam_option_names/
# wp_sam_automation_upgrade_notice hook names themselves -- those are the
# shared registry's own generic extension points and are expected to exist
# (with zero listeners) in this package; only what would REGISTER something
# through them is forbidden.
FORBIDDEN_STRINGS=(
  "fully_automatic"
  "Fully Automatic"
  "MODE_FULLY_AUTOMATIC"
  "wp_sam_stripe_"
  "wp_sam_webhook_secret"
  "wp_sam_create_checkout_session"
)

for needle in "${FORBIDDEN_STRINGS[@]}"; do
  if grep -rl --include="*.php" -F -- "${needle}" "${TARGET}" > /dev/null 2>&1; then
    echo "FORBIDDEN STRING present: ${needle}" >&2
    grep -rn --include="*.php" -F -- "${needle}" "${TARGET}" >&2
    FAILED=1
  fi
done

if [ "${FAILED}" -ne 0 ]; then
  echo "WordPress.org package verification FAILED." >&2
  exit 1
fi

echo "WordPress.org package verification passed: no forbidden paid-mode paths or identifiers found in ${TARGET}."
