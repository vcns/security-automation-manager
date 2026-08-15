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
| Unit tests | Covered | 38 test classes under `test/unit/`, run via `composer run test:no-coverage` in CI |
| WordPress integration tests | Missing | `test/bootstrap.php` loads hand-written stubs (`test/wp-admin/includes/upgrade.php`, etc.), not a real WordPress core checkout (no `WP_UnitTestCase`, no `wp-env`/`wp-cli scaffold` test suite). Everything currently called a "test" runs against stubs, not WordPress itself |
| Database migration tests | Partial | `SchemaMigrationTest.php` exists but runs against the stub environment, not a real WordPress DB with a prior-version schema loaded |
| Clean installation tests | Missing | No test installs the plugin into a real WordPress instance and asserts on activation-time state |
| Upgrade tests | Missing | No test exercises `2.4.x → 2.4.y` (or major version) upgrade against a real prior install |
| Rollback tests | Missing | Rollback is a manual SVN checklist in `docs/release-and-publishing.md`; no automated test exists (see #160) |
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

**Net:** of 23 categories, 4 are fully covered, 6 are partial, 13 are missing.
The single biggest structural gap is that nothing in CI currently runs against
a real WordPress instance — every "integration" test today runs against
hand-written stubs, which cannot catch a real WordPress core API change,
a real database migration failure, or a real activation-time fatal error.

## PHP / WordPress version matrix

### Declared support

- `readme.txt` / plugin header: `Requires at least: 6.4`, `Tested up to: 7.0`,
  `Requires PHP: 8.1`.

### Actually tested in CI

`.github/workflows/ci.yml`'s `php-lint-and-standards` job runs a single
configuration: **PHP 8.1, no WordPress version at all** (tests run against
stubs, not a WordPress core checkout). There is no matrix; no other PHP
version and no WordPress version is exercised anywhere in CI.

**This means "Tested up to: 7.0" in `readme.txt` is currently an unverified
claim** — nothing in the pipeline installs WordPress 7.0 (or any WordPress
version) and runs the plugin against it.

### Target matrix

Once WordPress integration tests exist (this issue's primary blocker — see
"Next steps"), CI should run the full cross-product below on every PR to
`main`:

| | PHP 8.1 | PHP 8.2 | PHP 8.3 |
|---|---|---|---|
| WordPress 6.4 (`Requires at least`) | Required | Required | Required |
| WordPress latest stable | Required | Required | Required |
| WordPress trunk/nightly | Optional (advisory, non-blocking) | Optional (advisory, non-blocking) | Optional (advisory, non-blocking) |

PHP 8.4 should be added to the matrix once `wp-coding-standards/wpcs` and the
plugin's own code are confirmed compatible (not yet verified either way).

## Next steps

1. Introduce a real WordPress test environment (`@wordpress/env` or
   `wp-cli scaffold plugin-tests` + `svn co` of the WordPress test library)
   so `WP_UnitTestCase`-based tests can run against actual WordPress core,
   not hand-written stubs. This unblocks clean-install, upgrade, multisite,
   and uninstall testing simultaneously — it's the one change that closes
   the largest number of "Missing" rows above.
2. Extend `ci.yml`'s job (or add a matrix job) across the PHP/WordPress grid
   in "Target matrix" above, using `actions/matrix` with
   `shivammathur/setup-php` for the PHP axis and the new integration harness
   for the WordPress axis.
3. Add an uninstall test: activate, seed representative data in every table
   and option this plugin creates, run `uninstall.php`, assert the database
   and options table are clean.
4. Add a schema-migration test that loads a prior-version database snapshot
   and asserts the upgrade path produces the expected current schema.
5. Once WP-CLI support (#184), configuration import (#185), and entitlement
   signing (#173/#174) land, add their test categories from the table above
   at the same time — do not ship the feature and defer its test category to
   a follow-up.
