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

Note: `sam-permissions-policy.png` predates the v2.9.x change that shortened
the "All" dropdown option's label and moved its explanation to a description
line below the table -- recapture it next time a fresh set of screenshots is
taken so it matches the current UI text exactly.

## Not yet used

Captured but not currently embedded anywhere. Certificates (ACME/TLS) has no
dedicated section in the help site at all yet -- that's a documentation gap,
not just a missing-image one, so its ten screenshots are listed but not
placed.

- `sam-certificates-csr.png`, `sam-certificates-install-cpanel.png`, `sam-certificates-install-pem.png`, `sam-certificates-install.png`, `sam-certificates-issuance.png`, `sam-certificates-key-types.png`, `sam-certificates-method.png`, `sam-certificates-providers-1.png`, `sam-certificates-providers.png`, `sam-certificates-staging.png`
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
