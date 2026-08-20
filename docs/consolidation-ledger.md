# Consolidation Ledger

## Purpose

This is the repository assessment and roadmap reconciliation for the
public-release consolidation effort: a verified, evidence-based snapshot of what
the plugin actually does today, checked directly against code, tests, CI
workflows, and every open roadmap issue rather than issue titles or changelog
claims. It is the baseline every later consolidation PR (documentation
correction, hardening, release verification, rollback, certificate assurance,
the commercial control plane) works from.

Resolves roadmap issue #151.

Every claim below cites a file, line, test, or `gh issue view` result. Where a
claim could not be verified, it is recorded as unverified rather than assumed.

## Repository identity

The plugin's `Plugin URI` header, release workflow, and update-manifest checker
all reference `vcns/security-automation-manager`. This checkout's `origin`
previously pointed at `vcns/csp-automation-manager`.

Verified 2026-08-18:

- `gh api repos/vcns/security-automation-manager` and
  `gh api repos/vcns/csp-automation-manager` both resolve to the same GitHub
  repository ID (`1258382520`) and both report `full_name` as
  `vcns/security-automation-manager` - `csp-automation-manager` is a historical
  name for the same repository (GitHub's rename-redirect), not a fork or a
  separate history.
- Local `HEAD` (`dc9d0871`) is byte-identical to
  `origin/release/2.9.2-risk-badge-tooltips` after a fresh fetch - 0 commits
  ahead, 0 behind. No unpushed or divergent commits.
- `origin` has been corrected to
  `https://github.com/vcns/security-automation-manager.git`. No change was made
  to the Plugin URI header, release workflow, or update-checker - they were
  already correct.

One residual observation, not a divergence: `release/2.9.2-risk-badge-tooltips`
carries one commit (`dc9d087`, "clean hash ref") not present on `main` - a
one-line copy edit to a risk-note string in
`includes/csp/class-policy-builder.php`, made after PR #233 was squash-merged.
It is pushed, trivial, and non-functional; it is not a blocker, but it means
`main` (not this release branch) is the correct base for new consolidation work.

## Repository assessment

| Fact | Value | Evidence |
|---|---|---|
| Plugin version | 2.9.2 | `security-automation-manager.php:6,24` |
| DB schema version | 22 | `security-automation-manager.php:121` |
| Latest release tag | v2.9.2 | `git tag --sort=-creatordate` |
| Open pull requests | 0 | `gh pr list --state open` |
| Open issues | 43 | `gh issue list --state open` |
| Supported WordPress | 6.4 – tested to 7.0 | `security-automation-manager.php:7`, `readme.txt` |
| Supported PHP | 8.1+ | `security-automation-manager.php:8` |

**Build channels.** One codebase, two build outputs, produced only by CI -
never by a runtime toggle a customer sets. `.distignore` plus
`release-package.yml` rsync two parallel trees; the WordPress.org tree has the
GitHub updater removed and gets no `Update URI` header, the GitHub tree keeps
it and gets `build-channel.php` injected. Exactly one zip is ever published as
a GitHub Release asset (`security-automation-manager-vX.Y.Z.zip`, the
GitHub-channel build); the WordPress.org-safe zip is a CI/SVN artifact only,
never a Release download.

**Update mechanism.** `Github_Update_Checker`
(`includes/modules/class-github-update-checker.php`) validates package host,
HTTPS scheme, path-traversal (`..` segments), `.zip` suffix, and SHA-256
checksum via `hash_equals()` before allowing an install, and is only
instantiated when `WP_SAM_DISTRIBUTION_CHANNEL === 'github'` (default is
`'wordpress-org'`). One updater; no second/conflicting update path.

**Commercial functionality.** All Stripe/checkout/webhook/entitlement code
lives in `offline/`, a git-ignored directory that ships empty in the public
repository; `class-plugin.php` wires it in only via `class_exists()`. No
Stripe secret exists in tracked files. `Feature_Gate` gates exactly one
capability - `fully_automatic` CSP mode - everything else is free regardless
of entitlement state, and an entitlement-check failure silently downgrades
that one mode to `automatic_high_approval` rather than disabling headers,
policies, or certificates. `docs/checkout-proxy-design.md` documents a
proposed VCNS-hosted control plane, explicitly marked unimplemented.

**Certificate functionality.** A complete ACME v2 subsystem under
`includes/certificates/`: `Acme_Client` (nonce/bad-nonce retry, account
registration, order/authorization polling, staging/production separation),
`Acme_Crypto` (EC-P256/RSA-2048 keygen, JWK/JWS, CSR construction, the 2.9.1
live keygen capability probe), `Certificate_Store`, `Credential_Vault`
(libsodium secretbox, versioned ciphertext), `Deployer` (cPanel UAPI,
webroot-traversal-checked export, manual download), `Renewal_Scheduler`
(WP-Cron, 30-day threshold, duplicate-event guards), and 41 DNS-01 provider
drivers behind a common interface.

**Existing tests.** One PHPUnit suite (`test/unit/`, 46 files). No WordPress
integration tests - `test/bootstrap.php` hand-stubs WP core and `wpdb` rather
than using `WP_UnitTestCase` or wp-env; `docs/testing-requirements.md` names
this as the single biggest gap. Certificate coverage is uneven: `Acme_Crypto`,
`Credential_Vault`, `Certificate_Store`, and DNS-provider registry shape are
tested; `Acme_Client`, `Certificate_Manager`, `Deployer`, `Challenge_Http`, and
`Renewal_Scheduler` are not.

**Package-validation and migration tests.** `VersionConsistencyTest.php`
cross-checks plugin-header version, `WP_SAM_VERSION`, readme.txt's stable tag,
and the latest CHANGELOG entry, plus the release workflow's channel-split
logic - narrow, and does not cover SPECIFICATION.md, SECURITY.md, or `docs/`.
`SchemaMigrationTest.php` covers fresh-install and legacy-to-current migration
against the hand-stubbed `wpdb`, not a live database with a genuine
prior-version schema.

**Rollback support.** None in code. The only artifact is a seven-line manual
checklist in `docs/release-and-publishing.md`. No mechanism identifies a
last-known-good release, snapshots data pre-rollback, detects a newer schema
than the target plugin, refuses an unsafe downgrade, or logs a rollback
attempt.

**CI matrix.** `ci.yml` (PHP 8.1 only - lint, PHPCS, PHPUnit, TruffleHog,
Semgrep, a plain package-audit build), `codeql.yml` (runs a second Semgrep
pass, not `github/codeql-action`, despite the name), `dast.yml` (ZAP baseline
against a live WordPress container), `pr-branch-policy.yml`,
`release-package.yml`, `wporg-deploy.yml`, `pages.yml`. No workflow tests more
than one PHP version or any WordPress version; none installs, upgrades, or
rolls back the plugin in a live WordPress instance.

**Existing documentation.** 20 files under `docs/`; four (security-privacy
checklist, testing-requirements, threat-model, data-protection-and-retention)
landed in commit `6ff06a9` and cite the roadmap issue they resolve.
`SPECIFICATION.md` is the significant outlier: its header declares alignment
to DB schema v4, 18 schema versions behind the live v22, while marked
"Status: Active."

## Documentation drift found

These are documented for the Phase 2 correction PR; nothing here has been
changed yet.

1. **GitHub release package naming.** README.md:80,82 still describes the
   pre-2.8.0 two-asset scheme and inverts the current single-asset naming.
2. **Automation default - self-contradicting.** README.md:28 says every
   surface defaults to `automatic_high_approval`; README.md:102 says
   automation defaults to Manual for every surface. Code (schema v18 migration
   note) confirms line 28 for fresh installs, and that this only changes who
   approves a proposed CSP *source*, never CSP enforcement.
3. **COOP/COEP report-only capability.** README.md:47 and readme.txt state the
   other nine pillars have no report-only mode. `page-cross-origin.php`
   implements a Disabled/Report-Only/Enforce selector and a Report-Only
   Evidence table (backed by `sam_pillar_violation_reports`, schema v13) for
   exactly COOP and COEP.
4. **Certificates undocumented.** Zero mentions in README.md or
   SPECIFICATION.md; readme.txt mentions certificates only in the external-services
   privacy disclosure and changelog, never in the feature description or
   `Tags:` line.
5. **SPECIFICATION.md stale at schema v4** against the live v22 - see above.

## Roadmap reconciliation

All 43 open issues, classified against direct evidence, not issue titles or
changelog claims.

**Corrected totals** (see "Note on the reconciliation count" below for why
these differ from the first pass of this assessment):

| Status | Count | Issues |
|---|---:|---|
| Implemented | 5 | #152, #153, #154, #155, #158 |
| Partially implemented | 12 | #151, #159, #160, #163, #164, #165, #166, #167, #171, #173, #179, #180 |
| Tracking gate (open by design) | 1 | #156 |
| Not applicable (governance, no code deliverable) | 1 | #189 |
| Not started | 24 | all remaining |

5 + 12 + 1 + 1 + 24 = 43.

### Phase 0 - foundational documentation

| Issue | Requirement | Status | Evidence | Remaining work | Recommendation |
|---|---|---|---|---|---|
| #151 | Repository assessment & gap analysis | Partial | This document supersedes the prior GH-comment assessment, which predated commit `6ff06a9` and the #158 UI work it claimed didn't exist. | None - this document is the completed assessment. | Update issue with this document, then close |
| #152 | Security & privacy checklist | Implemented | `docs/security-privacy-checklist.md`, cites #152 by number | Two of three live signing keys (Stripe webhook secret, Stripe API secret) still lack rotation/incident-response docs (self-flagged in the doc) | Close |
| #153 | Testing & CI matrix checklist | Implemented | `docs/testing-requirements.md` self-audits 23 test categories and the CI matrix | The gaps it documents are real (see #159) but are a separate issue, not unmet acceptance criteria for #153 | Close |
| #154 | Threat model | Implemented | `docs/threat-model.md` (241 lines): update pipeline, entitlements/control-plane, fleet-management sections | None against the issue's single acceptance criterion | Close |
| #155 | Data-protection & retention model | Implemented | `docs/data-protection-and-retention.md`, cites #155 by number | None | Close |
| #156 | Public-hosting readiness gate | **Tracking gate - not "not started"** | Blocker checklist posted as a GH comment, cross-references #151/#159/#160/#172 | By design, stays open until every feeding issue resolves. Confirmed still-unmet: SPECIFICATION.md still calls HSTS "outside this plugin's remit" despite it shipping; #172 (control plane) unresolved; #159/#160 gaps unresolved | Remain open; refresh its blocker checklist against this document |

### Phase 1 - release verification

| Issue | Requirement | Status | Evidence | Remaining work | Recommendation |
|---|---|---|---|---|---|
| #158 | Update Channel status section in admin UI | Implemented | `page-overview.php`:360-497 - every field in the issue body verified line-by-line: version, channel, manifest URL, last success/fail check, available version, background-update permission, `WP_SAM_DISABLE_AUTO_UPDATE` state, manifest/checksum status, last result, no-secrets note | None found | Close |
| #159 | Release verification test suite (18 scenarios) | Partial | 18 unit tests cover manifest-host rejection, checksum mismatch, slug/version validation. `release-verification.yml` (Phase 4) additionally covers clean install (both channels) and upgrade (from previous release and from the last pre-certificate release, v2.4.33) against a real WordPress + MySQL instance, with data-preservation and upgrade-idempotency assertions, and a real-network manifest-rejection proof against a mock server | Rollback (#160, separate issue), WP-UI-triggered upgrade, background-update-off, interrupted-update recovery beyond the idempotency proxy, expired transient, and cached manifest still have no coverage | Update - rollback tracked separately as #160; remaining scenarios are follow-up, not this phase's scope |
| #160 | Supported rollback process | Partial | `Rollback_Guard` (schema v23) now provides schema-downgrade detection and refusal, a persistent admin warning, pre-migration configuration snapshots, and same-schema-version restore -- validated against real WordPress + MySQL (`.github/workflows/release-verification.yml`'s `rollback-and-recovery` job) and unit-tested for the pure decision logic (`RollbackGuardTest.php`). `docs/rollback-and-recovery.md` covers the manual code-rollback process this can't automate | Cannot and will not swap the plugin's own PHP code back to an older release (a WordPress/hosting-level action, documented as manual); snapshot/restore covers configuration-state tables only, not a full-site backup | Update - core automatable scope delivered; remaining gap is inherent to what a running plugin can do to itself, not missing work |

### Phase 2 - spec, docs consistency, technical debt

| Issue | Requirement | Status | Evidence | Remaining work | Recommendation |
|---|---|---|---|---|---|
| #161 | Multi-domain specification (replace CSP-only spec) | Not started | SPECIFICATION.md still declares alignment to schema v4 | Full 12-domain rewrite | Remain open - Phase 2 |
| #162 | Full security-controls inventory doc | Not started | No inventory file exists | Full doc | Remain open |
| #163 | Documentation consistency audit + automated checks | Partial | `VersionConsistencyTest.php` checks 4 facts across 1 file; misses SPECIFICATION.md's schema-v4 staleness | Extend to SECURITY.md, COMMERCIAL_TERMS.md, `docs/*`, SPECIFICATION.md | Update - folded into Phase 2 |
| #164 | Triage `code-review-findings.json` | Partial | No entry has a formal disposition field, but #165-#170 below effectively answer each one | Formalise dispositions in the JSON itself | Update |
| #165 | Approved-source pagination | Partial | `page-csp-dashboard.php`:465-478 - clamp/preserve-filters/empty-state all present | No regression test with more rows than page size | Update - fix shipped, test owed |
| #166 | Unconditional cross-tab dashboard queries | Partial | Unbounded full-scan hazard fixed (queries now tab-scoped); 4 small bounded queries (profiles, violations LIMIT 50, conflict notices LIMIT 5, scan logs LIMIT 20) still run on every tab load | Tighten remaining unconditional queries; add the instrumentation the issue asks for | Update |
| #167 | Standardise pagination validation across admin tables | Partial | Shared `Table_Query` pattern applied across CSP dashboard and cross-origin evidence table; `TableQueryTest.php` covers the shared renderer | Per-table regression proof, not just the shared helper | Update |
| #168 | PHPUnit bootstrap / stub loading order | Not started | `bootstrap.php`:38 autoloads, then requires `NonceBridge.php` ~750 lines later; `offline/` fallback still live in tests | Reorder bootstrap; remove untracked-directory dependency from tests | Remain open |
| #169 | Improve `wpdb::prepare()` test stub | Not started | Stub regex handles only `%s`/`%d`/`%%` | Add `%f`, `%i`, LIKE handling, invalid-argument handling | Remain open |
| #170 | Dependency boundary for `Policy_Builder` data loading | Not started | `class-policy-builder.php`:459,476 - `protected` loader methods, no injected collaborator | Repository/DI boundary | Remain open |

### Phase 3 - commercial & distribution boundary

| Issue | Requirement | Status | Evidence | Remaining work | Recommendation |
|---|---|---|---|---|---|
| #171 | Formalise WordPress.org vs VCNS GitHub distribution boundary | Partial | De facto pattern exists: `class-plugin.php`:237-239 gates commercial classes behind `class_exists()` on `offline/` | Document the pattern formally; decide if it needs a stronger boundary than "directory is gitignored" | Update |
| #172 | VCNS hosted control plane for Stripe/entitlements | Not started | `docs/checkout-proxy-design.md` exists, explicitly marked unimplemented; no Stripe code in `includes/` | Full build - Phase 8, kept separate from free-plugin stabilisation | Remain open |
| #173 | Plugin-side entitlement data model | Partial | `class-feature-gate.php`:41-96 already has an `Entitlement_Store`-shaped interface, `is_pro()`, entitlement cache | Formalise schema against the existing shape | Update |
| #174 | Fail-safe entitlement validation with grace periods | Not started | `class-feature-gate.php` has no grace-period/outage logic - boolean pass-through only | Grace-period design and implementation | Remain open |

### Phase 4 - posture, drift, evidence, resilience (deferred)

| Issue | Requirement | Status | Evidence | Recommendation |
|---|---|---|---|---|
| #175 | Security posture score, 11-state model | Not started | Only `class-risk-badge.php` (5-level per-source CSP risk badge) exists | Remain open - deferred |
| #176 | Generalised drift detection | Not started | SRI drift and competing-header detection are already implemented and targeted (out of this issue's scope); nothing generalised exists | Remain open - deferred; cite existing targeted drift as prior art |
| #177 | Time-bound exceptions | Not started | No exception-record concept found | Remain open - deferred |
| #178 | Compliance evidence pack export | Not started | No export/pack code found | Remain open - deferred |
| #179 | Safe policy simulation and promotion gates | Partial | `class-policy-change-manager.php`:177-178 builds proposal records with risk level/reason; no full diff/rollback-point UI | Update - note existing scaffolding, still deferred as a full feature |
| #180 | Backup, pre-update snapshot, and restore | Partial | `class-policy-version-manager.php` snapshots/compares CSP policy versions only, not full plugin state | Update - note narrower existing scope, still deferred as a full feature |
| #181 | Security regression testing baselines | Not started | No baseline-comparison code found | Remain open - deferred |

### Phase 5 - deferred integrations

| Issue | Requirement | Status | Recommendation |
|---|---|---|---|
| #182 | Scheduled external verification service | Not started | Remain open - deferred |
| #183 | Webhook and SIEM integrations | Not started (inbound Stripe webhook setting exists, unrelated) | Remain open - deferred |
| #184 | WP-CLI command support | Not started (only a `defined('WP_CLI')` SAPI guard) | Remain open - deferred |
| #185 | Configuration-as-code import/export | Implemented | `Config_Portability` exports/imports administrator-authored configuration (policy profiles, source/hash approvals, other pillar profiles, dependency classifications, non-secret certificate settings, automation/reporting options) as JSON via the Recovery tab; allowlist-based on both table and option names, never secrets/credentials/audit log/violation history | Update - close pending authorisation |

### Phase 6 - fleet & multisite (deferred)

| Issue | Requirement | Status | Recommendation |
|---|---|---|---|
| #186 | WordPress Multisite support | Not started | Remain open - deferred |
| #187 | Compatibility knowledge base | Not started | Remain open - deferred |
| #188 | Fleet-management data model | Not started | Remain open - deferred |
| #189 | Sequence fleet management behind real-world validation | N/A - governance/go-no-go tracking issue, no code deliverable | Defer-confirmed |
| #190 | Local and remote recommendation engine | Not started | Remain open - deferred |

### Admin-nav restructure

| Issue | Requirement | Status | Evidence | Recommendation |
|---|---|---|---|---|
| #219 | Restructure admin navigation into grouped sections | Not started | `class-admin-ui.php`:110-215 - flat sequence of ~11 `add_submenu_page()` calls | Remain open |
| #220 | Information Masking section | Not started | Zero matches for Server/X-Powered-By masking or `expose_php` handling | Remain open |
| #221 | Session & Cache Control section, competing-mechanism detection | Not started | Zero matches for Cache-Control anywhere in `includes/` | Remain open |
| #222 | Legacy headers section (X-XSS-Protection, Expect-CT) | Not started | Zero matches for either header | Remain open |

## Note on the reconciliation count

The first pass of this assessment (delivered before this document was
committed) reported "7 implemented" in its summary while naming only five
issues (#152, #153, #154, #155, #158). That was a counting error, not a
reference to two additional issues - re-verifying against every agent
transcript and re-checking the code directly, no other issue meets the bar for
"Implemented." The corrected count is **5 implemented**, and the partial count
is **11**, not 10 (the first pass undercounted by omitting #151 itself from
its own partial bucket). Table above is the corrected version.

## Proposed closures

Recommended for closure, pending explicit authorisation (none of these have
been closed):

- #152, #153, #154, #155, #158

Not recommended for closure: #151 (update with this document, then close),
#156 (tracking gate, stays open by design), everything else (partial or not
started).

## Remaining release blockers

Ordered by what most directly stops a defensible public release:

1. ~~**No rollback mechanism**~~ (#160) - **the automatable scope delivered
   in Phase 5**: `Rollback_Guard` detects and refuses an unsafe automatic
   downgrade, snapshots configuration state before every forward migration,
   and restores a snapshot when the running code's schema still matches.
   What remains is inherent to what a running plugin can do to itself, not
   missing work -- swapping the plugin's own PHP code back to an older
   release is a manual, documented process
   (`docs/rollback-and-recovery.md`), the same as it is for every WordPress
   plugin.
2. **No VCNS control plane** (#172) - blocks the *commercial* Fully Automatic
   service specifically; does not block a free GitHub-channel or
   WordPress.org release, since commercial code is already excluded from both
   builds today.
3. ~~**SPECIFICATION.md is 18 schema versions stale** while marked "Active"
   (#161)~~ — **fixed in PR #236** (Phase 2), replaced with an authoritative
   v1.0 covering all product domains, released as v2.9.4. #161 itself should
   still be formally closed with a reference to this document; not done
   automatically per the standing "don't close issues without authorisation"
   rule.
4. ~~**README contains two direct self-contradictions and one inverted
   naming) - **fixed in PR #236** (Phase 2 of the consolidation sequence),
   released as v2.9.4.
5. ~~**No install/upgrade/rollback test runs against a real WordPress
   instance**~~ (#159) - **the install/upgrade half fixed in Phase 4**:
   `.github/workflows/release-verification.yml` now runs clean install (both
   channels), upgrade from the previous release, upgrade from the last
   pre-certificate release, and data-preservation assertions against a real
   `wordpress` + MySQL instance via WP-CLI, plus a real-network manifest-
   rejection proof. The *rollback* half remains genuinely open - see item 1
   above (#160) - and #159 itself still has real gaps against its original
   18-scenario list (WP-UI-triggered upgrade, background-update-off, expired
   transient, cached manifest, and a few others have no coverage in any
   form); see `docs/testing-requirements.md` for the current, honest
   accounting.
6. ~~Certificate capability-probe leaks raw OpenSSL error text to the admin
   UI~~ - **fixed in Phase 3** of the consolidation sequence: the
   administrator-facing message is now a stable, generic string
   (`Acme_Crypto::GENERATION_FAILURE_MESSAGE`); the raw diagnostic is still
   shown, demoted to a collapsed "Technical detail" disclosure rather than
   presented as the primary explanation. Was already low-severity
   (admin-only, XSS-safe) - this was hardening, not a release blocker, per
   the consolidation decision that scoped Phase 3. The credential vault's
   SHA-256-based key derivation was formally assessed in the same phase
   (`docs/credential-vault-assessment.md`) and deliberately left unchanged -
   the assessment found the derivation itself defensible, but documented a
   real gap (no rotation support; a vault-key change silently blanks
   already-stored secrets with no recovery path) as follow-up work, not
   something to fix by changing the format without the migration+recovery
   design that document specifies.
7. DNS-01 provider driver test coverage needs a verified provider-by-provider
   accounting before any "tested" claim is made publicly - see Phase 6 of the
   consolidation sequence.

## Methodology

Built from direct inspection of the working tree, git history, CI workflow
files, and `gh issue view` against all 43 open issues - no claim above is
sourced from an issue title or changelog line alone.

## Refresh - 2026-08-20

Everything above is left unedited as the historical record from 2026-08-18.
This section supersedes only the facts that have since changed, verified
directly against the current checkout and `gh issue`/`gh pr` output. The
43-issue reconciliation table above is **not** repeated - live evidence
confirms its per-issue findings still hold (see "Issue closures" below for
the five that were re-checked in full); only the aggregate counts have moved.

### Repository identity - re-verified, unchanged

`origin` is still `https://github.com/vcns/security-automation-manager.git`
(fetch and push). Local `HEAD` was byte-identical to `origin/main` before
this refresh's own commits, 0 ahead / 0 behind, no divergent or unpushed
commits. No `csp-automation-manager` remote exists in this checkout. The
2026-08-18 correction held; nothing needed re-fixing.

### Repository assessment - updated facts

| Fact | 2026-08-18 value | Current value | Evidence |
|---|---|---|---|
| Plugin version | 2.9.2 | 2.9.19 | `security-automation-manager.php:24` |
| DB schema version | 22 | 25 | `security-automation-manager.php:147` |
| Latest release tag | v2.9.2 | v2.9.19 | `git tag --sort=-creatordate` |
| Open issues | 43 | 42 before this refresh's closures; **37 after** (see "Issue closures" below) | `gh issue list --state open --limit 200` |

All other facts in the original "Repository assessment" table (build
channels, update mechanism, commercial functionality, certificate
functionality's component list, CI workflow names) were spot-checked and
still hold structurally; the certificate-functionality and testing rows are
superseded in full by the Phase 6 assessment below rather than patched here.

### Merged PRs since Phase 5 (#244)

28 PRs merged 2026-08-18T14:28 through 2026-08-20T08:09 (#245-272). None
delivers Phase 6, 7, or 8 as scoped in this consolidation plan. Grouped:

- **#245, #247** - release-version bumps for the Phase 5 rollback work and
  the Recovery-tab work below (no additional scope of their own).
- **#246** - Recovery tab: splits Reset Plugin Data out of Readiness, adds
  configuration export/import. Product feature work, tracked under #180's
  narrower existing scope (see the original table above), not part of this
  consolidation sequence.
- **#248-267** - the CSP hash-inventory production-incident response: ten
  releases fixing unbounded `csp_hash_inventory` growth (silent 500s),
  rate-limiting the resulting audit notices, a non-deterministic cutoff bug,
  the root cause itself (nonce-covering `wp_add_inline_style()` blocks), a
  visual-contrast fix, and an empty-inline-attribute-hash allowlist fix.
  None touches Certificates, the update pipeline, or entitlements - no
  overlap with Phase 6.
- **#268-269** - Bypass Best Practices catalog expansion (3 to 9 entries,
  schema v25) and a labelling follow-up. Also updates
  `docs/threat-model.md`'s Bypass Best Practices section (already covered by
  this refresh's #154 evidence - see "Issue closures" below).
- **#270** - help-site diagram; docs-only, no code.
- **#271-272** - WordPress.org submission remediation (`.distignore` fix,
  then a full Plugin Check findings pass - see "Release and WordPress.org
  submission position" below).

No PR was found that explicitly delivers Phase 6, 7, or 8. Per the standing
instruction not to treat that as proof the phases are wholly outstanding
without checking: the Phase 6 code assessment below does exactly that check
for Phase 6 specifically, against the certificate subsystem directly rather
than PR titles. It found no later PR delivers any part of Phase 6's scope -
see that section for the evidence. Phases 7 and 8 were not separately
re-investigated in this refresh; nothing in the 28 PRs above touches release-
candidate hosting-environment validation (Phase 7) or a VCNS-hosted control
plane (Phase 8) by title or diff content reviewed here.

### Release and WordPress.org submission position

- GitHub-channel release process unchanged and healthy: v2.9.19 is tagged,
  released, and its update feed published. `wporg-deploy.yml` still skips
  gracefully - the WordPress.org SVN repository does not exist yet (initial
  plugin review pending).
- A manual WordPress.org "Add your plugin" submission attempt failed
  automated scanning on two ERRORs (self-updater / `Update URI` header
  detected). Root cause: the GitHub-channel release asset was uploaded
  instead of the WordPress.org-channel build, which only ever existed as a
  CI artifact, never a downloadable Release asset. Fixed by building and
  independently verifying a correct WordPress.org-channel zip; PR #271 also
  closed a real, unrelated gap it surfaced (`CONTRIBUTORS.md`, and, for the
  future SVN auto-deploy path specifically, the self-updater file, were both
  missing from `.distignore`).
- A follow-up scan of the corrected zip via WordPress Playground's Plugin
  Check tool returned roughly 600 findings. PR #272 fixed the seven that
  were real (two `ABSPATH` guards placed past the scanner's apparent line
  window, `readme.txt`'s `Tested up to`/short-description/changelog limits,
  two broken `phpcs:ignore` placements on multi-line statements, two missing
  `fread()` suppression comments matching an already-established pattern on
  the same socket, one discouraged-function call now scoped to the channel
  that actually needs it) and left the remainder as individually-verified
  false positives, documented in that PR's description, per the scan's own
  instruction not to work around unconfirmed findings without reviewer
  input.
- **Net position:** not yet resubmitted. No blocking ERROR is currently
  known to remain in the WordPress.org-channel build, but this has not been
  re-verified against a fresh Plugin Check run since PR #272 merged - that
  re-run, not further code changes, is the next step before resubmission.

### Issue closures

Five issues re-checked against current code and documentation, not just the
2026-08-18 evidence citations, before closing:

- **#152, #153, #154, #155, #158** - all confirmed still satisfied. One real
  gap found during re-verification: `docs/security-privacy-checklist.md`
  itself stated its Stripe-key incident-response runbook "should be treated
  as part of closing #152, not deferred" - an unchecked follow-up item, not
  a closed one. That runbook is now written (same section of the same
  file), closing the gap on its own terms rather than closing over it.
  `docs/threat-model.md` was also missing the "Resolves roadmap issue #154"
  citation line every sibling document has; added for consistency (the
  document's content already fully satisfied #154's acceptance criterion).
  See each issue's closing comment for the specific evidence.
- **#159, #160** - left open, per instruction. Descriptions updated to
  state only the scenarios genuinely still uncovered, since the two-days-old
  evidence in the original table above (Rollback_Guard, schema v23,
  `release-verification.yml`) has not changed - it was re-confirmed as still
  present and unmodified since Phase 4/5, not re-derived.
- **#156** - left open, as the public-hosting readiness gate. Unchanged.

Resulting open-issue count: **37** (42 minus the five closures above).
