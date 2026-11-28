# WordPress × PHP compatibility matrix

Runtime checks of SAM on real WordPress in Docker. Not shipped: `tools/` is in `.distignore`.

```bash
cd tools/docker-matrix && npm install && npx playwright install chromium   # once
bash tools/docker-matrix/run.sh 7.2 8.6        # one environment
KEEP=1 bash tools/docker-matrix/run.sh 7.2 8.6 # leave it running at http://localhost:8726
ONLY=c,d bash tools/docker-matrix/run.sh 6.4 8.1  # a subset of the browser checks
```

`run.sh` does the following:

1. Builds the image and starts MySQL 8.0 and WordPress.
2. Installs WordPress with `admin` and `editor` users.
3. Runs checks a to g.
4. Writes everything to `results/<wp>-<php>/` and tears the environment down.

`results/` is git-ignored.

## Environments

The plugin checkout is mounted read-only at `wp-content/plugins/security-automation-manager`. `wp-config.php` sets `WP_DEBUG`, `WP_DEBUG_LOG`, `SCRIPT_DEBUG` (so jQuery Migrate's JQMIGRATE warnings show) and `DISABLE_WP_CRON`. Instead of relying on WP-Cron, `run.sh` runs due cron events once with WP-CLI, so SAM's scheduled code is covered by check b.

Each environment uses its own port, `8<wp digits><php minor>` (for example 8726 for 7.2 × 8.6). Apache listens on that port inside the container too, so the site URL works from the host browser and for WordPress's own loopback requests.

| WordPress | PHP | Base image | Core in the image |
|---|---|---|---|
| 6.4 | 8.1 | `wordpress:6.4-php8.1-apache` | 6.4.3 |
| 6.4 | 8.3 | `wordpress:6.4-php8.3-apache` | 6.4.3 (PHP 8.3.4) |
| 7.1 | 8.1 | `php:8.1-apache`, core downloaded | 7.1.5 |
| 7.1 | 8.4 | `wordpress:7.1-php8.4-apache` | 7.1.5 |
| 7.2 | 8.1 | `php:8.1-apache`, core downloaded | 7.2-RC3 |
| 7.2 | 8.3 | `wordpress:beta-php8.3-apache` | 7.2-RC3 |
| 7.2 | 8.5 | `wordpress:beta-php8.5-apache` | 7.2-RC3 |
| 7.2 | 8.6 | `wordpress:beta-php8.6-apache` | 7.2-RC3 (PHP 8.6.0, no imagick) |

Notes on the table:

- **Tags:** these were checked with `docker manifest inspect` on 2026-11-26, and the image contents with `php -r` against `wp-includes/version.php`.
- **No official image for WordPress 7.1 or 7.2 on PHP 8.1:** there is no `wordpress:7.1-php8.1-apache`. `wordpress:beta-php8.1-apache` still exists but stopped updating at 6.9-RC4. Both pairs are therefore built from `php:8.1-apache`, with the extensions WordPress needs installed by [docker-php-extension-installer](https://github.com/mlocati/docker-php-extension-installer) and core fetched with `wp core download`. Set `WP71_CORE` or `WP72_CORE` to use another release (`nightly` works too).
- **Registry:** images come from `public.ecr.aws/docker/library`, Amazon's mirror of Docker Hub's official images with the same digests. Docker Hub's anonymous pull limit ran out while building this. Set `REGISTRY=docker.io/library` to use Docker Hub. Each run records the exact digest in `env.txt`.
- **Browser:** Playwright 1.65.1's Chromium, version 159. That is new enough for WordPress 7.2's client-side media, which needs Chromium 137 or later.

## Client address

Traffic Guard reads only `REMOTE_ADDR`, and it never rate-limits loopback or private addresses. The browser reaches the container through the Docker gateway (172.16.0.0/12), so every request would count as the server calling itself.

To avoid that, the browser sends `X-Forwarded-For: 198.51.100.23`, an address from a documentation range, and `mod_remoteip` in the image puts it into `REMOTE_ADDR`. This is the same topology as a production site behind a CDN, where the web server puts the visitor's real address into `REMOTE_ADDR`.

## Checks

| | What | Where |
|---|---|---|
| a | Activate, deactivate and reactivate succeed; `wp_sam_db_version` equals `WP_SAM_DB_VERSION` after each activation | `activation.log` |
| b | `debug.log` has no PHP notice, warning, deprecation or fatal from a SAM file, read after every other check | `debug.log`, `debug-sam.log` |
| c | As admin, visit the five stage pages, every SAM page linked from them, and every slug in `Admin_UI::print_hidden_menu_css()`'s `$hidden_slugs`. Record SAM console errors, page errors and JQMIGRATE warnings (attributed by stack), any HTTP 5xx, and a missing `<h1>`. One screenshot per page at deviceScaleFactor 1. | `browser.json`, `screenshots/` |
| d | The SAM menu icon renders, the visible submenu is exactly Settings, Observe, Decide, Control, Verify, and every hidden slug is hidden | `browser.json` → `menu`, `screenshots/admin-menu.png` |
| e | Under the admin CSP in three setups (report-only; enforce with defaults; enforce with `worker_src_blob` and `script_src_wasm_unsafe_eval`), upload a JPEG three ways: in the Media Library grid, at `media-new.php`, and through the block editor's own `mediaUpload`. Then check the block editor's editing canvas, open the media window with a real click on *Set featured image*, and open the Media Library's list view. For each, record core's client-side flag (`window.__clientSideMediaProcessing`, WordPress 7.1+), `crossOriginIsolated`, the isolation headers, the upload route (REST sideload/finalize, REST without sideload, or `async-upload.php`) and the violations SAM stored. **e1:** report-only, every path works. **e2/e3:** enforced, `media-new.php`, the editor upload and the list view work. **e-editor:** enforced, the editing canvas loads. **e-grid:** enforced, the grid and the media window. | `browser.json` → `media` |

Code a check runs through Playwright's `page.evaluate()` goes through the DevTools protocol, which exempts it from the page's `'unsafe-eval'` rule. Anything that has to show what a user gets under CSP is therefore triggered by a real click or by the page's own code, never from `evaluate()`.
| f | With the API surface enforcing default limits, the editor uploads 30 images in one batch, twice: through the media modal (`wp.media`), then through the block editor's own `mediaUpload`, which is the path 7.2's client-side processing takes. Record REST request counts, the peak per 60 seconds, any 403/429/503, and SAM's `sam_traffic_blocks` rows for the client. | `browser.json` → `traffic` |
| g | `wp plugin uninstall --deactivate --skip-delete` (the mount is read-only) leaves no `wp_sam_*`/`wp_csp_*` tables and no `wp_sam_*` options or transients | `uninstall.log` |

`checks.tsv` holds one line per check: id, pass, fail or not run, and the detail.
