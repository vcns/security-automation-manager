# Rollback and Recovery

## Purpose

Resolves roadmap issue #160. `docs/release-and-publishing.md`'s "Rollback
Planning" section is the operator-facing checklist for deciding *whether* to
roll back a bad release; this document is the detailed *how*, for both what
the plugin automates and what still requires a manual database backup
restore.

Read this before attempting to downgrade a production site, not while
already mid-incident -- the single most useful thing you can do to make any
rollback safe is take a full database backup *before* you start, and that's
easy to forget under pressure.

## What this plugin can and cannot do to itself

A running WordPress plugin cannot swap its own PHP files back to an older
release. That happens at the WordPress/hosting level -- uploading an older
ZIP through **Plugins → Add New Plugin → Upload Plugin**, restoring a file
backup, or `wp plugin install <url-to-old-zip> --force` via WP-CLI. Nothing
in this plugin can do that step for you.

What `Rollback_Guard` (`includes/class-rollback-guard.php`, schema v23) does
provide, automatically:

1. **Refuses an unsafe automatic migration.** Every plugin boot checks
   whether the installed database schema is *ahead* of the running code's
   schema version -- the state produced when older code gets installed over
   a database a newer version already migrated. If so, no migration runs.
   `Activator::activate()`'s `dbDelta()` calls only know how to add columns
   and tables, never remove ones a newer schema introduced, and several of
   its migration functions (e.g. tightening a CSP default) assume they're
   moving a site forward. Running them against a database that's already
   ahead risks silently wrong behaviour, not a clean downgrade.
2. **Shows a persistent admin notice** for as long as that mismatch exists,
   and a matching entry (`component: rollback`, `event:
   schema_downgrade_detected`) in the audit log (Security Automation
   Manager → CSP → Policy Audit, or query `sam_audit_log` directly).
3. **Snapshots configuration state before every forward migration.**
   Immediately before schema N → N+1 runs, every row of the config-state
   tables (CSP policy profiles, source/hash approvals, the other header
   pillars' profiles, dependency/SRI classifications, certificate records)
   is captured into `sam_migration_snapshots`, keeping the last 5. This
   deliberately excludes the audit log and other log-shaped tables --
   nothing ever overwrites those, so they need no snapshot.
4. **Lets you restore a snapshot** from **Security Automation Manager →
   Recovery → Rollback and Recovery**, but only when the
   running code's schema still matches exactly what that snapshot was taken
   for. This undoes a migration's *data* effects (e.g. a default that
   changed in a way you don't want) while staying on current code. It
   cannot restore across a schema change to a different code version --
   that case is refused with a clear reason, not attempted partially.

## Deciding whether you need this document at all

| Situation | What to do |
|---|---|
| A migration changed data you don't like, but the *new* plugin version is otherwise fine | Use the snapshot restore on the Recovery tab -- see above. No manual steps needed. |
| You need to go back to an *older plugin version* (a regression, an incompatibility) | Follow "Manual code rollback" below. |
| The site shows the schema-downgrade notice after an unplanned reinstall of older code | Follow "Recovering from an unintended downgrade" below. |
| A migration itself failed partway (PHP timeout, fatal error, server crash) | See "Recovery after an interrupted migration" below -- this is usually self-healing, no action needed. |

## Manual code rollback

1. **Identify the last known-good version.** Check
   [the GitHub Releases page](https://github.com/vcns/security-automation-manager/releases)
   or `CHANGELOG.md` for the version before the one causing trouble, and
   read its changelog entry for the DB schema version it shipped with
   (`security-automation-manager.php`'s `WP_SAM_DB_VERSION` history
   docblock lists what each schema version changed).
2. **Take a full database backup first**, not just of this plugin's tables
   -- a hosting-level or `wp db export` backup, before touching anything.
   This is the actual safety net if the steps below don't go cleanly; the
   plugin's own snapshot mechanism (above) only covers its own
   configuration tables, not a full-site backup.
3. **Record the current state** before you start: current plugin version
   (`wp plugin list`), current schema version (`wp option get
   wp_sam_db_version`), and the current time, so you have a clear "before"
   reference.
4. **Deactivate the plugin** (`wp plugin deactivate
   security-automation-manager`) -- this stops header emission and any
   cron-triggered actions (certificate renewal, scheduled scans) while you
   work.
5. **Replace the plugin files** with the older version (upload, WP-CLI
   `--force` install, or restore from a file backup).
6. **Do not reactivate yet.** Check what schema version the older code
   expects (its own `WP_SAM_DB_VERSION` docblock) against what's actually
   installed (`wp option get wp_sam_db_version`, still readable while the
   plugin is deactivated).
   - **If the installed schema matches or is behind** what the older code
     expects: reactivating is safe -- the older code's own upgrade path
     will run normally.
   - **If the installed schema is *ahead*** (the common case -- you're
     downgrading past a schema change): reactivating will trigger
     `Rollback_Guard`'s downgrade detection, which is the intended,
     safe outcome -- the plugin will refuse to touch the database and show
     the persistent warning. It will **not** work correctly in this state
     (older code doesn't understand newer schema/data), so treat the
     warning as confirmation you need step 7, not as the finish line.
7. **If the schema is ahead of the older code:** the only supported path is
   restoring the full database backup from step 2 as well, then
   reactivating the older plugin files against that restored (older-schema)
   database. This is the situation automatic recovery deliberately refuses
   to attempt silently -- guessing at how to reverse a schema change safely
   is exactly the kind of behaviour that could corrupt certificate records
   or encrypted credentials.
8. **Verify**: on the Readiness tab, the schema version matches what the
   reactivated code expects; on the Recovery tab, the downgrade notice is
   gone; and spot-check that policy profiles, certificates, and any
   DNS-provider credentials still look correct.

## Recovering from an unintended downgrade

If you see the schema-downgrade admin notice and didn't intend to roll
back:

1. **Do nothing destructive.** The plugin has already refused to touch the
   database -- that's the safe state. Existing header emission and cron
   jobs continue running under the last-known schema; nothing is being
   silently corrupted while the notice is showing.
2. **Reinstall the newer plugin version** that matches (or exceeds) the
   schema version named in the notice.
3. Reactivating will clear the notice automatically (`Rollback_Guard::
   clear_downgrade_flag_if_resolved()`) and log the recovery to the audit
   log.

## Recovery after an interrupted migration

`Activator::activate()` runs several `dbDelta()` calls and migration
functions in sequence, only marking the schema "verified" at the very end.
If a migration is interrupted partway (a PHP timeout, a fatal error, a
server crash mid-request), the next page load re-runs the same sequence
from the top. This is safe by design, not by luck: every migration function
in `Activator` checks before it mutates (an option is only copied if the
new key isn't already set; a directive is only stripped if it still exactly
matches the old default; a profile row is only inserted if one doesn't
already exist for that surface) -- re-running the full sequence against a
partially-migrated database is a no-op for whatever already completed and
picks up wherever it left off. This property is exercised directly in
`.github/workflows/release-verification.yml`'s upgrade-idempotency check,
which re-runs the upgrade path twice more after a real migration and
asserts nothing changes on the second and third pass.

If you suspect an interrupted migration left the site in a bad state beyond
what re-running fixes (a fatal error that recurs on every load, for
example), that's a bug report, not a rollback scenario -- capture the PHP
error log and open an issue rather than attempting a downgrade.

## What is and isn't covered by the snapshot/restore feature

**Covered** (snapshotted before every migration, restorable when the code's
schema still matches): CSP policy profiles and their directives, approved
sources and hashes, the other nine header pillars' per-surface profiles,
External Scripts/Internal Script Integrity classifications, and certificate
records (including their encrypted private-key and account-key fields, as
opaque ciphertext -- see the next section).

**Never touched, and so never needs restoring**: the audit log
(append-only by design), CSP violation reports, scan logs, and the policy
decision ledger -- restoring old rows into any of these would corrupt their
role as an immutable history.

**Not covered by this feature at all**: the plugin's own PHP code (see
"Manual code rollback" above), and DNS-provider/cPanel credentials'
*decryptability* if `WP_SAM_CERT_VAULT_KEY` or WordPress's own
`AUTH_KEY`/`AUTH_SALT` change independently of a plugin version change --
see `docs/credential-vault-assessment.md` for that specific risk, which
exists regardless of rollback and isn't something a schema-level snapshot
can protect against.

## Encrypted credentials and certificates across a rollback

Certificate private keys, ACME account keys, and DNS-provider/cPanel
credentials are encrypted at rest via `Credential_Vault`, keyed from
`WP_SAM_CERT_VAULT_KEY` (if defined in `wp-config.php`) or WordPress's own
`wp_salt('auth')` otherwise. Neither of these changes as a side effect of a
plugin version change, so a database-only rollback (restoring an older or
snapshotted database against the *same* `wp-config.php`) preserves
decryptability correctly. If `wp-config.php` was *also* restored to an
older version as part of a fuller site restore, and that older
`wp-config.php` defined a *different* `WP_SAM_CERT_VAULT_KEY` value, every
certificate/credential sealed under the newer key becomes permanently
unrecoverable -- there is no way to decrypt data sealed under a key you no
longer have. Confirm `wp-config.php`'s vault-related constants (or absence
of them) match what was in effect when the data you're restoring was
sealed, before assuming certificates and credentials will still work after
a rollback.
