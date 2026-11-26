#!/bin/sh
# Container entrypoint for the matrix's wordpress service.
#
# Apache listens on APACHE_PORT, the same port the host publishes, so
# http://localhost:APACHE_PORT is this site's URL both in the browser on
# the host and for loopback requests WordPress makes from inside the
# container (wp-cron, Site Health, SAM's own fetches of its well-known
# files).
set -eu

PORT="${APACHE_PORT:-80}"
sed -ri "s/^Listen [0-9]+$/Listen ${PORT}/" /etc/apache2/ports.conf
sed -ri "s/<VirtualHost \*:[0-9]+>/<VirtualHost *:${PORT}>/" /etc/apache2/sites-available/000-default.conf

# First start: copy core into the shared volume. The plugin is a read-only
# bind mount inside wp-content/plugins, which this copy never touches.
if [ ! -f /var/www/html/wp-includes/version.php ]; then
	cp -a /usr/src/wordpress/. /var/www/html/
	chown www-data:www-data /var/www/html /var/www/html/wp-content /var/www/html/wp-content/plugins
	cat > /var/www/html/.htaccess <<'HTACCESS'
# BEGIN WordPress
<IfModule mod_rewrite.c>
RewriteEngine On
RewriteRule .* - [E=HTTP_AUTHORIZATION:%{HTTP:Authorization}]
RewriteBase /
RewriteRule ^index\.php$ - [L]
RewriteCond %{REQUEST_FILENAME} !-f
RewriteCond %{REQUEST_FILENAME} !-d
RewriteRule . /index.php [L]
</IfModule>
# END WordPress
HTACCESS
	chown www-data:www-data /var/www/html/.htaccess
fi

exec docker-php-entrypoint "$@"
