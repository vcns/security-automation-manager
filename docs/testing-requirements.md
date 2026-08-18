# Testing Requirements and CI Matrix

## Purpose

Section 21 of the roadmap specification lists the categories of automated and
manual testing required across the roadmap, plus a requirement that CI exercise
every supported PHP/WordPress combination that's practical. As with the
security/privacy checklist, this lives here once rather than being copied into
39 issues; every roadmap issue's acceptance criteria carries an implicit
"Cross-cutting requirements: see `docs/testing-requirements.md`" footer.

Resolves roadmap issue #153. Complements `docs/testing-and-quality.md`, which
covers the general local-validation baseline; this document is the specific
checklist and the CI matrix audit.

## Test category coverage

Status as of this audit (2026-08). "Covered" means an automated test exists and
runs in CI. "Partial" means some scenarios in the category are covered but
material gaps remain. "Missing" means no automated coverage exists.

| Category | Status | Notes |
|---|---|---|
| Unit tests | Covered | 38+ test classes under `test/unit/`, run via `composer run test:no-coverage` in CI |
| WordPress integration tests | Partial | `test/bootstrap.php` still loads hand-written stubs for the `test/unit/` PHPUnit suite (no `WP_UnitTestCase`, no `wp-env`/`wp-cli scaffold` test suite -- that specific gap remains, see "Next steps"). `.github/workflows/release-verification.yml` closes the practical gap a different way: real `wordpress` + real MySQL containers, driven by WP-CLI, covering clean install, upgrade, and data preservation (see rows below) |
| Database migration tests | Partial | `SchemaMigrationTest.php` still runs against the stub environment. `release-verification.yml`'s upgrade jobs now additionally run the real migration path (schema v20 → current, and the immediately-previous release → current) against a real WordPress database, asserting the post-migration schema version and table set directly |
| Clean installation tests | Covered | `release-verification.yml` installs and activates the plugin in a real WordPress + MySQL instance for both distribution channels, asserting schema version, table set, and (GitHub channel only) that the update checker actually attaches to WordPress's own `pre_set_site_transient_update_plugins` filter, not just that its class file is autoloadable |
| Upgrade tests | Covered | `release-verification.yml`'s `upgrade-and-preservation` job upgrades a real install from the immediately-previous release and from the last pre-certificate release (v2.4.33, schema v20) to the current checkout, asserting the schema version advances and re-running the upgrade check twice more to prove it's idempotent (a proxy for interrupted-update recovery -- a real mid-copy interruption is WP core's own file-replacement mechanism, outside this plugin's control) |
| Rollback tests | Missing | Rollback is a manual SVN checklist in `docs/release-and-publishing.md`; no automated test exists (see #160, prioritised next after this) |
| Multisite tests | Missing | `SPECIFICATION.md` explicitly documents multisite as unsupported; no test coverage expected until #186 |
| REST API tests | Partial | `WebhookControllerTest.php`, `ReportingEndpointTest.php`, `AdminUITest.php` cover specific routes against stubs; no test asserts on the full registered REST route table or permission callbacks as a set |
| WP-CLI tests | Missing | No WP-CLI commands exist yet (#184); nothing to test |
| Package-content tests | Covered | `release-package.yml`'s `package-audit` job builds the distribution ZIP and asserts (via `unzip -l` grep) that WordPress.org-excluded paths are absent |
| Update-manifest validation | Partial | `GithubUpdateCheckerTest.php` covers manifest-host allowlisting and version/slug validation; no test validates the manifest JSON schema itself end-to-end |
| Checksum validation | Covered | `GithubUpdateCheckerTest.php` covers `hash_equals()` checksum-mismatch rejection |
| Entitlement signature validation | Missing | No signature scheme currently exists for entitlements (see #173/#174 and the checkout-proxy design) |
| Replay resistance | Partial | `WebhookControllerTest.php` covers the Stripe webhook 5-minute timestamp tolerance; no equivalent exists yet for any future entitlement or config-signing channel |
| Exception expiry | Missing | Time-bound exceptions (#177) aren't implemented yet |
| Drift detection | Missing | Drift detection (#176) isn't implemented yet |
| Posture scoring | Missing | Posture scoring (#175) isn't implemented yet |
| Evidence exports | Missing | Evidence-pack export (#178) isn't implemented yet |
| Configuration imports | Missing | Configuration-as-code import (#185) isn't implemented yet |
| External verification result processing | Missing | External verification service (#182) isn't implemented yet |
| Audit-log creation | Covered | Audit-log write paths are exercised indirectly through the test classes that trigger them (policy changes, entitlement changes); no dedicated `AuditLogTest.php` asserting on entry shape/completeness across all trigger points |
| Permission boundaries | Partial | Individual REST tests assert on their own `permission_callback`; no single test enumerates every registered route and asserts none is missing a capability check |
| Uninstall and data-retention behaviour | Missing | `uninstall.php` exists and lists options/tables to remove, but no automated test runs uninstall and asserts the database is clean afterward |

**Net:** of 23 categories, 6 are fully covered, 6 are partial, 11 are missing.
The single biggest structural gap -- nothing in CI ran against a real
WordPress instance -- is now partially closed: `release-verification.yml`
covers clean install, upgrade, and data-preservation scenarios against a real
`wordpress` + MySQL instance via WP-CLI. What remains open is a
`WP_UnitTestCase`-based PHPUnit integration suite for the existing
`test/unit/` tests themselves (still stub-based) -- a different mechanism
covering more granular, per-class assertions than a shell-driven workflow
can reasonably express. See "Next steps" below.

## PHP / WordPress version matrix

### Declared support

- `readme.txt` / plugin header: `Requires at least: 6.4`, `Tested up to: 7.0`,
  `Requires PHP: 8.1`.

### Actually tested in CI

`.github/workflows/ci.yml`'s `php-lint-and-standards` job now runs the
`test/unit/` PHPUnit suite (still stub-based, not a WordPress core checkout)
across a real PHP version matrix: **PHP 8.1, 8.2, 8.3, and 8.4** (PHPCS runs
once, on 8.1, since a style violation is a property of the code, not the PHP
version). `release-verification.yml` separately runs against real WordPress
core (`wordpress:6.7-php8.1-apache`) via Docker, currently pinned to a single
WordPress version rather than the WordPress axis below -- WordPress
version-matrix coverage for that workflow remains open, see "Next steps".

**"Tested up to: 7.0" in `readme.txt` is still not directly verified** --
`release-verification.yml` currently runs against WordPress 6.7 (matching
`dast.yml`'s existing container), not 7.0. Confirming 7.0 compatibility
remains open work.

### Target matrix

CI should run the full cross-product below on every PR to `main`. PHP is now
covered for the stub-based unit suite; the WordPress axis for
`release-verification.yml` is the remaining gap:

| | PHP 8.1 | PHP 8.2 | PHP 8.3 | PHP 8.4 |
|---|---|---|---|---|
| WordPress 6.4 (`Requires at least`) | Unit: yes / WP: no | Unit: yes / WP: no | Unit: yes / WP: no | Unit: yes / WP: no |
| WordPress latest stable (7.0) | Unit: yes / WP: no | Unit: yes / WP: no | Unit: yes / WP: no | Unit: yes / WP: no |
| WordPress trunk/nightly | Not run | Not run | Not run | Not run |

"Unit" = the stub-based `test/unit/` suite (PHP-version-sensitive, WordPress-
version-insensitive since it never loads WordPress core). "WP" =
`release-verification.yml`'s real-WordPress jobs (currently pinned to 6.7 on
PHP 8.1 only). Extending "WP" across this matrix is future work; each
combination roughly triples that workflow's already-substantial runtime, so
it should land as a scheduled/nightly job rather than on every PR once added.

## Next steps

1. ~~Introduce a real WordPress environment for clean-install and upgrade
   testing~~ -- done via `release-verification.yml` (Docker + WP-CLI, not
   `@wordpress/env`/`WP_UnitTestCase` -- see the note below on why both still
   have a place).
2. ~~Extend `ci.yml`'s job across a PHP matrix~~ -- done: PHP 8.1-8.4 for the
   `test/unit/` suite.
3. A `WP_UnitTestCase`-based integration harness (`@wordpress/env` or
   `wp-cli scaffold plugin-tests` + `svn co` of the WordPress test library)
   is still open work, and is a different thing from
   `release-verification.yml`: it would let the *existing* `test/unit/`
   classes assert against real WordPress core objects/hooks instead of
   `test/bootstrap.php`'s stubs, catching a real WordPress core API change at
   the unit-test level rather than only at the full-lifecycle level
   `release-verification.yml` operates at. Multisite and uninstall testing
   (below) are natural fits for this harness once it exists.
4. Add an uninstall test: activate, seed representative data in every table
   and option this plugin creates, run `uninstall.php`, assert the database
   and options table are clean.
5. Extend `release-verification.yml`'s WordPress axis to cover more than one
   WordPress version (currently pinned to 6.7) -- see the "Target matrix"
   note on running this as scheduled/nightly rather than per-PR once it
   covers more than one WordPress version, given the runtime cost.
6. Add rollback testing once #160 lands (prioritised immediately after this
   in the consolidation sequence -- see `docs/consolidation-ledger.md`).
7. Once WP-CLI support (#184), configuration import (#185), and entitlement
   signing (#173/#174) land, add their test categories from the table above
   at the same time - do not ship the feature and defer its test category to
   a follow-up.
