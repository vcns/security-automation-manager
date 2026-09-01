# Screenshot inventory

The original 7-shot placeholder list this file used to track has been captured
and wired into the public help site (`docs/user-guide.html`, `docs/index.html`)
under the real filenames below -- the placeholders (`admin-overview-page.png`,
`csp-profiles-tab.png`, etc.) never matched an actual file and rendered as
broken images on the live site until this was fixed.

## Wired into a page

| Filename | Used in |
|---|---|
| `sam-overview.png` | user-guide.html (First 30 minutes) |
| `sam-navigation.png` | index.html (Dashboard) |
| `sam-security-layers.svg` | index.html (Start here) |
| `sam-csp-profile.png` | user-guide.html (How it works) |
| `sam-csp-for-review.png` | user-guide.html (Scan and learn) |
| `sam-csp-policy-changes.png` | user-guide.html (Approval workflow) |
| `sam-csp-settings-deterministic-automation.png` | user-guide.html (Automation tiers) |
| `sam-permissions-policy.png` | user-guide.html (The other nine pillars) |
| `sam-x-frame-options.png` | user-guide.html (The other nine pillars) |
| `sam-x-content-type-options.png` | user-guide.html (The other nine pillars) |
| `sam-referrer-policy.png` | user-guide.html (The other nine pillars) |
| `sam-hsts.png` | user-guide.html (The other nine pillars) |
| `sam-cross-origin-coop.png` | user-guide.html (The other nine pillars) |
| `sam-cross-origin-coep.png` | user-guide.html (The other nine pillars) |
| `sam-reverse-tabnabbing.png` | user-guide.html (Content rewrite protections) |
| `sam-scripts-external.png` | user-guide.html (Content rewrite protections) |
| `sam-scripts-internal.png` | user-guide.html (Content rewrite protections) |
| `sam-certificates-method.png` | user-guide.html (TLS certificates) |
| `sam-certificates-providers.png` | user-guide.html (TLS certificates) |
| `sam-certificates-key-types.png` | user-guide.html (TLS certificates) |
| `sam-certificates-csr.png` | user-guide.html (TLS certificates) |
| `sam-certificates-staging.png` | user-guide.html (TLS certificates) |
| `sam-certificates-issuance.png` | user-guide.html (TLS certificates) |
| `sam-certificates-install.png` | user-guide.html (TLS certificates) |
| `sam-certificates-install-pem.png` | user-guide.html (TLS certificates) |
| `sam-certificates-install-cpanel.png` | user-guide.html (TLS certificates) |

`sam-certificates-providers-1.png` was deliberately left out of the TLS
certificates section -- it's the same DNS provider dropdown as
`sam-certificates-providers.png`, scrolled to a different position, and adds
no information the other doesn't already show.

## Not yet used

Captured but not currently embedded anywhere.

- `sam-certificates-providers-1.png` (redundant duplicate, see above)
- `sam-cross-origin-corp.png`, `sam-cross-origin-xpcd.png`, `sam-cross-origin-policies.png` (tab bar only), `sam-cross-origin-coop-violations.png`, `sam-cross-origin-coep-violations.png`
- `sam-csp-manual-scan.png`, `sam-csp-policy-audit.png`, `sam-csp-scan-log.png`, `sam-csp-start-here.png`, `sam-csp-violations.png`
- `sam-csp-settings-promotion-gates.png`, `sam-csp-settings-proxy-header.png`, `sam-csp-settings-report-endpoint-learning.png`, `sam-csp-settings-scheduled-scan.png`
- `sam-notice-csp-source-conflicts.png`
- `sam-readiness.png`, `sam-readiness-operational-health.png`
- `sam-recovery-import-export.png`, `sam-recovery-reset-plugin-data.png`, `sam-recovery-rollback-options.png`
- `sam-scripts-external-inventory.png`, `sam-scripts-internal-hash-inventory.png`, `sam-scripts-start-here.png`
- `sam-updates-manifest.png`

Keep using the `sam-` prefix and descriptive suffix convention for anything
new -- it's what made mapping these back to specific admin pages possible
without having to open the WordPress admin to check.
