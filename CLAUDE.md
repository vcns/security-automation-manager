# Notes for AI agents working on this repository

Read this before changing anything a site administrator will see. It records conventions that can't be worked out reliably from the code alone, and mistakes agents have already made here.

## Admin navigation: describe routes the way staff see them

Since 2.10.0 (Customer-Centred Administration Experience), the WordPress left-hand menu shows exactly five SAM items: **Settings, Observe, Decide, Control, Verify**. (Advanced Intelligence was a sixth item through 2.11.4; its tabs are now linked from the stages instead.) The user-facing map of this is the "for orientation" diagram in `docs/user-guide.html`.

Every other SAM page is still registered in `Admin_UI::add_menu_pages()`, but `Admin_UI::print_hidden_menu_css()` hides it from the menu. The hide is CSS only, so direct URLs keep working for technical users. The `$hidden_slugs` list in that method is the definitive record of what's hidden. Check it rather than assuming: an agent once misread it and declared a visible page unreachable. That means the titles passed to `add_submenu_page()` are **not** the navigation. Neither is a hidden page's own `<h1>` or tab bar. Don't infer where something lives from `add_menu_pages()`. The hidden pages include CSP, Scripts, Traffic Controls, Certificates, Continuous Intelligence, Baseline & Drift, Advanced Intelligence, HSTS, Cross-Origin Policies, Reverse Tabnabbing and the other per-pillar pages.

**Rule.** User-facing text that tells someone where to go names the route as they click it. Write it as the stage, then the link text on that stage's own page, then a tab if needed, joined with `→`. For example, write "Decide → Dependency Classification", never "the External Scripts page". This applies to:

- admin notices,
- recommendations and Action Centre items,
- Security Health details,
- help text that points to another page,
- `readme.txt` changelog entries.

A link's URL should match the one that stage's page uses. On a page, referring to that page's own tabs ("on the Violations tab") is fine. If a destination has no route from the five stages, don't invent one: flag it.

`Admin_UI::admin_notice_action()` labels follow this rule, and `AdminUITest` asserts that every notice-link label starts with one of the five stages.

### Route table

Taken from `includes/admin/views/page-{observe,decide,control,verify}.php` and `page-overview.php` (Settings). `PageLifecycleTest` covers the Advanced Intelligence links. Re-check those files if a lifecycle page changes.

| Destination | Route staff use | URL (`admin.php?page=…`) |
|---|---|---|
| CSP violation reports | Observe → CSP Violations | `security-automation-manager-dashboard&tab=violations` |
| CSP discovery scan history | Observe → Scan Log | `security-automation-manager-dashboard&tab=scan-log` |
| Request observation, identities, vendors | Observe → Continuous Intelligence | `security-automation-manager-intelligence` |
| Site changes, drift and campaigns in one chronological view | Observe → Timeline | `security-automation-manager-advanced&tab=timeline` |
| CSP sources awaiting a decision | Decide → For Review | `security-automation-manager-dashboard&tab=sources` |
| CSP decision ledger | Decide → Policy Changes | `security-automation-manager-dashboard&tab=policy-changes` |
| Possible coordinated activity (many IPs, one detector) | Decide → Campaigns | `security-automation-manager-advanced&tab=campaigns` |
| Effective CSP per surface | Verify → CSP Policy Audit (also Decide → Policy Audit) | `security-automation-manager-dashboard&tab=policy-audit` |
| Exceptions | Settings → Exceptions (also Decide → Active Exceptions) | `security-automation-manager&tab=exceptions` |
| Third-party script/stylesheet origins (SRI, pinning) | Decide → Dependency Classification | `security-automation-manager-scripts&tab=external` |
| Rate limits, IP rules, blocks, network intelligence, detectors, custom rules | Control → Traffic Controls → *tab* | `security-automation-manager-traffic&tab=…` |
| CSP mode per surface | Control → CSP Profiles | `security-automation-manager-dashboard&tab=profiles` |
| CSP automation level | Control → Automation Settings | `security-automation-manager-dashboard&tab=settings` |
| TLS certificates | Control → Certificates (also Verify → Certificates) | `security-automation-manager-certificates&tab=renew` |
| Decoy paths | Control → Honey Paths | `security-automation-manager-advanced&tab=honeypaths` |
| File/theme/plugin drift | Verify → Baseline & Drift | `security-automation-manager-baseline` |
| Declared change windows and what drifted during them | Verify → Change Windows | `security-automation-manager-advanced&tab=change-windows` |
| Every layer and pillar with its status (the per-layer tables) | Settings → All | `security-automation-manager&tab=all` |
| Header pillars (HSTS, X-Frame-Options, …), Reverse Tabnabbing | Settings → All → that pillar's row → Manage | `security-automation-manager&tab=all`, whose Manage link opens the `page` in `Admin\Pillar_Registry` |
| Rollback, configuration export/import | Settings → Recovery | `security-automation-manager&tab=recovery` |

## Other conventions that have caught agents out

- **`readme.txt` changelog.** Keep only the 15 most recent releases, plus the "Full changelog history" link. `VersionConsistencyTest` fails PHPUnit on every PHP version once the section passes 4,000 words (WordPress.org truncates at 5,000). When you add a release entry, trim the oldest. `CHANGELOG.md` keeps everything.
- **CI.** A PR isn't ready to merge until its CI has finished green (`gh pr checks <n> --watch`). Local PHPUnit runs on a different PHP version and isn't a substitute.
- **Releases.** A branch going to `main` that will be deployed to WordPress.org must be named exactly `release/vX.Y.Z`; `wporg-deploy.yml` rejects anything else. See `docs/release-and-publishing.md`.
- **New root-level files ship in the plugin ZIP.** `.distignore` lists root Markdown files individually, so add any new one there.
