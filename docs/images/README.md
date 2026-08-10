# Screenshot shot list

The public help site references these files as placeholders (broken-image icons
until captured). Each `<img>` tag already has descriptive `alt` text describing
the shot; this file is the capture checklist.

Recommended capture setup: a disposable WordPress instance with this plugin
mounted, matching `.github/workflows/dast.yml`'s own setup --

```bash
docker network create wp-shots 2>/dev/null || true
docker run -d --name wp-shots-db --network wp-shots \
  -e MYSQL_DATABASE=wordpress -e MYSQL_USER=wordpress \
  -e MYSQL_PASSWORD=wordpress -e MYSQL_ROOT_PASSWORD=root \
  mysql:8.0
docker run -d --name wp-shots-app --network wp-shots -p 8080:80 \
  -e WORDPRESS_DB_HOST=wp-shots-db -e WORDPRESS_DB_USER=wordpress \
  -e WORDPRESS_DB_PASSWORD=wordpress -e WORDPRESS_DB_NAME=wordpress \
  -v "$PWD":/var/www/html/wp-content/plugins/security-automation-manager \
  wordpress:6.7-php8.1-apache
```

Then complete the install wizard at `http://localhost:8080`, activate the
plugin, and capture at a consistent browser width (1280px is what the site's
`.screenshot` component is designed around).

| Filename | Used in | What to show |
|---|---|---|
| `admin-overview-page.png` | user-guide.html | **Overview** page: per-pillar status table for all ten pillars. |
| `admin-menu-structure.png` | index.html | The WordPress admin left-hand nav with the **Security Automation Manager** top-level menu expanded, showing all 14 submenu items. |
| `csp-profiles-tab.png` | user-guide.html | **CSP -> Profiles** tab: per-surface mode selector, ideally with at least one surface not on Manual. |
| `csp-for-review-tab.png` | user-guide.html | **CSP -> For Review** tab with at least a few pending sources visible (run a manual scan against a real site first so the table isn't empty). |
| `csp-policy-changes-tab.png` | user-guide.html | **CSP -> Policy Changes** tab showing a few decisions in the ledger (approve/reject at least one source first). |
| `csp-settings-automation-upgrade.png` | user-guide.html | **CSP -> Settings**, Deterministic Automation table, with Fully Automatic visibly marked "(requires upgrade)" and the Upgrade button showing (needs a build without an active entitlement -- the default state). |
| `permissions-policy-page.png` | user-guide.html | **Permissions-Policy** page: the per-surface, per-feature None/Self/All matrix. |

Keep filenames exactly as listed -- the HTML already references these paths
relative to `docs/` (e.g. `images/csp-profiles-tab.png`).
