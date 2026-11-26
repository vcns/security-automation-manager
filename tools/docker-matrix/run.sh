#!/usr/bin/env bash
# Runs SAM's compatibility checks against one WordPress x PHP environment.
#
#   tools/docker-matrix/run.sh <wp> <php>      e.g. run.sh 7.2 8.6
#
# Brings the environment up, installs WordPress with an admin and an editor,
# activates SAM, runs checks a-g (see README.md), saves everything to
# tools/docker-matrix/results/<wp>-<php>/, and tears the environment down.
# KEEP=1 leaves it running; ONLY=c,d limits the browser checks.
set -uo pipefail
export MSYS_NO_PATHCONV=1 # Git Bash: don't rewrite /paths in docker arguments.

WP="${1:?usage: run.sh <wp> <php>}"
PHP="${2:?usage: run.sh <wp> <php>}"
DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$DIR/../.." && pwd)"
SLUG="${WP}-${PHP}"
OUT="$DIR/results/$SLUG"
export REGISTRY="${REGISTRY:-public.ecr.aws/docker/library}"

# ── Environment table (README.md records why each base was chosen) ──────
case "$SLUG" in
6.4-8.1) BASE="wordpress:6.4-php8.1-apache" CORE="" ;;
6.4-8.3) BASE="wordpress:6.4-php8.3-apache" CORE="" ;;
7.1-8.1) BASE="php:8.1-apache" CORE="${WP71_CORE:-7.1.5}" ;;
7.1-8.4) BASE="wordpress:7.1-php8.4-apache" CORE="" ;;
7.2-8.1) BASE="php:8.1-apache" CORE="${WP72_CORE:-7.2-RC3}" ;;
7.2-8.3) BASE="wordpress:beta-php8.3-apache" CORE="" ;;
7.2-8.5) BASE="wordpress:beta-php8.5-apache" CORE="" ;;
7.2-8.6) BASE="wordpress:beta-php8.6-apache" CORE="" ;;
*)
	echo "No environment defined for WordPress $WP with PHP $PHP" >&2
	exit 2
	;;
esac
export BASE_IMAGE="$REGISTRY/$BASE"
export WP_VERSION="${CORE:-$WP}"
export PHP_VERSION="$PHP"
export HTTP_PORT="8${WP//./}${PHP#8.}"
# Docker Desktop on Windows needs a Windows path for the bind mount.
PLUGIN_DIR="$(cd "$ROOT" && (pwd -W 2>/dev/null || pwd))"
export PLUGIN_DIR
PROJECT="sam-${SLUG//./-}"
# Docker on Windows reads /c/... as C:\c\..., so hand it Windows-form paths.
COMPOSE_FILE_PATH="$(cd "$DIR" && (pwd -W 2>/dev/null || pwd))/docker-compose.yml"
URL="http://localhost:$HTTP_PORT"

compose() { docker compose -p "$PROJECT" -f "$COMPOSE_FILE_PATH" --profile cli "$@"; }
wp() { compose run --rm -T cli "$@"; }
# WP-CLI inside the wordpress container, where http://localhost:$HTTP_PORT is this site.
wpx() { compose exec -T -u www-data -e HOME=/tmp wordpress wp "$@"; }
sql() { compose exec -T db mysql -N -B -uwordpress -pwordpress wordpress -e "$1" 2>/dev/null; }
check() { printf '%s\t%s\t%s\n' "$1" "$2" "$3" | tee -a "$OUT/checks.tsv"; }
log() { printf '[%s %s] %s\n' "$(date +%H:%M:%S)" "$SLUG" "$*"; }

teardown() {
	if [ "${KEEP:-0}" != "1" ]; then
		compose down -v --remove-orphans >/dev/null 2>&1
	else
		log "KEEP=1: left running at $URL"
	fi
}
trap teardown EXIT

rm -rf "$OUT"
mkdir -p "$OUT"
: >"$OUT/checks.tsv"
# Native tools on Windows (node, docker cp) read /c/... as C:\c\..., so they get this form.
OUT_NATIVE="$(cd "$OUT" && (pwd -W 2>/dev/null || pwd))"

# ── Up ───────────────────────────────────────────────────────────────────
log "building $BASE_IMAGE (WordPress $WP_VERSION, PHP $PHP) on port $HTTP_PORT"
compose build wordpress >"$OUT/build.log" 2>&1 || {
	check setup fail "image build failed, see build.log"
	exit 1
}
compose up -d db wordpress >"$OUT/up.log" 2>&1 || {
	check setup fail "compose up failed, see up.log"
	exit 1
}
for _ in $(seq 1 90); do
	code="$(curl -s -o /dev/null -w '%{http_code}' "$URL/wp-includes/images/blank.gif" || true)"
	[ "$code" = "200" ] && break
	sleep 2
done
[ "$code" = "200" ] || {
	check setup fail "WordPress never answered on $URL"
	exit 1
}

wp config create --dbname=wordpress --dbuser=wordpress --dbpass=wordpress --dbhost=db --skip-check --force --extra-php >"$OUT/wp-cli.log" 2>&1 <<'PHP'
define( 'WP_DEBUG', true );
define( 'WP_DEBUG_LOG', true );
define( 'WP_DEBUG_DISPLAY', false );
define( 'SCRIPT_DEBUG', true );
define( 'DISABLE_WP_CRON', true );
define( 'FS_METHOD', 'direct' );
PHP
wp core install --url="$URL" --title="SAM matrix $SLUG" --admin_user=admin --admin_password=matrix-admin-pass \
	--admin_email=admin@example.test --skip-email >>"$OUT/wp-cli.log" 2>&1 || {
	check setup fail "wp core install failed, see wp-cli.log"
	exit 1
}
wp user create editor editor@example.test --role=editor --user_pass=matrix-editor-pass >>"$OUT/wp-cli.log" 2>&1
wp rewrite structure '/%postname%/' >>"$OUT/wp-cli.log" 2>&1
# Without this every SAM page redirects the admin to the first-run
# Personal Preferences page (Admin_UI::maybe_redirect_to_welcome()), so
# check c would only ever see that one page. It is still visited directly.
wp user meta update admin wp_sam_presentation_onboarding_state skipped >>"$OUT/wp-cli.log" 2>&1
# Proves debug.log is being written, so an empty SAM grep in check b means
# "no messages", not "no log".
wpx eval 'trigger_error( "sam-matrix debug.log probe", E_USER_NOTICE );' >>"$OUT/wp-cli.log" 2>&1

{
	echo "slug=$SLUG"
	echo "base_image=$BASE_IMAGE"
	echo "base_image_digest=$(docker image inspect "$BASE_IMAGE" --format '{{index .RepoDigests 0}}' 2>/dev/null | sed 's/.*@//')"
	echo "wordpress=$(wp core version 2>/dev/null)"
	echo "php=$(compose exec -T wordpress php -r 'echo PHP_VERSION;')"
	echo "php_extensions=$(compose exec -T wordpress php -m | grep -E '^(gd|imagick|intl|mysqli|zip|exif)$' | tr '\n' ' ')"
	echo "mysql=$(sql 'SELECT VERSION()')"
	echo "wp_cli=$(wp --version 2>/dev/null)"
	echo "plugin_commit=$(git -C "$PLUGIN_DIR" rev-parse --short HEAD)"
	echo "url=$URL"
} >"$OUT/env.txt"
log "$(tr '\n' ' ' <"$OUT/env.txt")"

# ── a) activation, deactivation, reactivation, schema version ───────────
expected_db="$(grep -o "define( *'WP_SAM_DB_VERSION', *'*[0-9][0-9]*" "$ROOT/security-automation-manager.php" | grep -o '[0-9][0-9]*$' | head -1)"
a_detail=""
a_ok=1
step() { # step <label> <wp args...>
	local label="$1"
	shift
	if out="$(wp "$@" 2>&1)"; then
		a_detail+="$label ok; "
	else
		a_ok=0
		a_detail+="$label FAILED ($(echo "$out" | tail -1)); "
	fi
	echo "== $label: $out" >>"$OUT/activation.log"
}
step activate plugin activate security-automation-manager
db1="$(wp option get wp_sam_db_version 2>/dev/null)"
step deactivate plugin deactivate security-automation-manager
[ "$(wp plugin is-active security-automation-manager >/dev/null 2>&1 && echo yes)" = "yes" ] && {
	a_ok=0
	a_detail+="still active after deactivate; "
}
step reactivate plugin activate security-automation-manager
db2="$(wp option get wp_sam_db_version 2>/dev/null)"
tables="$(sql "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema='wordpress' AND (table_name LIKE 'wp\\_sam\\_%' OR table_name LIKE 'wp\\_csp\\_%')")"
[ "$db1" = "$expected_db" ] && [ "$db2" = "$expected_db" ] || a_ok=0
check a "$([ $a_ok = 1 ] && echo pass || echo fail)" "${a_detail}schema v$db1 after activation, v$db2 after reactivation, release v$expected_db; $tables SAM tables"

# Run each of SAM's scheduled events once, so its cron code is in the
# debug.log check. They run in the wordpress container, where this site's
# URL is reachable (SAM's crawl and its own well-known file fetches use it).
sam_hooks="$(wpx cron event list --fields=hook --format=csv 2>/dev/null | grep -E '^(wp_sam|sam_)' | sort -u)"
echo "SAM events: $(echo "$sam_hooks" | paste -sd' ' -)" >"$OUT/cron.log"
for hook in $sam_hooks; do
	timeout 300 docker compose -p "$PROJECT" -f "$COMPOSE_FILE_PATH" exec -T -u www-data -e HOME=/tmp wordpress \
		wp cron event run "$hook" >>"$OUT/cron.log" 2>&1 || echo "event $hook did not finish cleanly (rc $?)" >>"$OUT/cron.log"
done

# ── c-f) browser checks ──────────────────────────────────────────────────
hidden="$(sed -n '/\$hidden_slugs = array(/,/);/p' "$ROOT/includes/admin/class-admin-ui.php" | grep -o "'security-automation-manager[a-z-]*'" | tr -d "'" | paste -sd, -)"
log "browser checks"
(cd "$DIR" && node checks.mjs --base="$URL" --wp="$(wp core version 2>/dev/null)" --out="$OUT_NATIVE" --project="$PROJECT" \
	--compose="$COMPOSE_FILE_PATH" --hidden="$hidden" --only="${ONLY:-c,d,e,f}" >"$OUT/checks-node.log" 2>&1) ||
	log "checks.mjs exited non-zero (see checks-node.log)"
cat "$OUT/checks.tsv" | grep -E '^(c|d|e|e[0-9]|f|browser)\b' || true

# ── g) uninstall ─────────────────────────────────────────────────────────
# The plugin directory is a read-only mount, so uninstall runs uninstall.php
# without deleting the files (--skip-delete), the same code path as
# "Delete" in wp-admin up to the file removal.
log "uninstall"
g_out="$(wp plugin uninstall security-automation-manager --deactivate --skip-delete 2>&1)"
g_rc=$?
left_tables="$(sql "SELECT table_name FROM information_schema.tables WHERE table_schema='wordpress' AND (table_name LIKE 'wp\\_sam\\_%' OR table_name LIKE 'wp\\_csp\\_%')" | paste -sd' ' -)"
left_options="$(sql "SELECT option_name FROM wp_options WHERE option_name LIKE 'wp\\_sam\\_%' OR option_name LIKE '\\_transient%wp\\_sam\\_%' OR option_name LIKE 'sam\\_%'" | paste -sd' ' -)"
{
	echo "$g_out"
	echo "tables left: ${left_tables:-none}"
	echo "options left: ${left_options:-none}"
} >"$OUT/uninstall.log"
if [ $g_rc -eq 0 ] && [ -z "$left_tables" ] && [ -z "$left_options" ]; then
	check g pass "uninstall.php ran; no wp_sam_*/wp_csp_* tables and no wp_sam_* options or transients left"
else
	check g fail "rc=$g_rc; tables left: ${left_tables:-none}; options left: ${left_options:-none}"
fi

# ── b) debug.log, after every step above ────────────────────────────────
compose cp wordpress:/var/www/html/wp-content/debug.log "$OUT_NATIVE/debug.log" >/dev/null 2>&1 || : >"$OUT/debug.log"
grep -E 'PHP (Notice|Warning|Deprecated|Fatal error|Parse error)|Uncaught' "$OUT/debug.log" | grep 'plugins/security-automation-manager/' >"$OUT/debug-sam.log" || true
other="$(grep -cE 'PHP (Notice|Warning|Deprecated|Fatal error|Parse error)' "$OUT/debug.log" || true)"
sam_count="$(wc -l <"$OUT/debug-sam.log" | tr -d ' ')"
if ! grep -q 'sam-matrix debug.log probe' "$OUT/debug.log"; then
	check b fail "debug.log was not written (the probe notice is missing), so this check could not run"
elif [ "$sam_count" = "0" ]; then
	check b pass "no notices, warnings, deprecations or fatals from SAM files; $((other - 1)) other PHP messages, none from SAM"
else
	check b fail "$sam_count from SAM files, e.g. $(sort -u "$OUT/debug-sam.log" | sed 's/^\[[^]]*\] //' | head -3 | cut -c1-300 | paste -sd'|' -)"
fi

compose logs --no-log-prefix wordpress >"$OUT/apache.log" 2>&1
log "done: $(cut -f1,2 "$OUT/checks.tsv" | paste -sd' ' -)"
