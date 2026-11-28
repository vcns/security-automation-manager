# WordPress runtime for the SAM compatibility matrix (tools/docker-matrix).
#
# BASE_IMAGE is chosen by run.sh from WP_VERSION and PHP_VERSION -- see
# README.md for the table and why. An official wordpress:*-apache image
# already has the extensions WordPress needs and a core copy in
# /usr/src/wordpress. A bare php:*-apache image (used where no official
# image exists for the pair) gets the same extensions here, and core is
# downloaded at WP_VERSION.
ARG BASE_IMAGE
FROM ${BASE_IMAGE}

ARG WP_VERSION
ARG PHP_VERSION
ARG WP_CLI_URL=https://raw.githubusercontent.com/wp-cli/builds/gh-pages/phar/wp-cli.phar
ARG PHP_EXT_INSTALLER_URL=https://github.com/mlocati/docker-php-extension-installer/releases/latest/download/install-php-extensions

RUN set -eux; \
	curl -fsSL -o /usr/local/bin/wp "$WP_CLI_URL"; \
	chmod +x /usr/local/bin/wp; \
	if [ ! -f /usr/src/wordpress/wp-includes/version.php ]; then \
		curl -fsSL -o /usr/local/bin/install-php-extensions "$PHP_EXT_INSTALLER_URL"; \
		chmod +x /usr/local/bin/install-php-extensions; \
		install-php-extensions mysqli gd intl zip exif bcmath opcache; \
		install-php-extensions imagick || echo "imagick unavailable for PHP ${PHP_VERSION}"; \
		mkdir -p /usr/src/wordpress; \
		php -d memory_limit=512M /usr/local/bin/wp core download --version="$WP_VERSION" --path=/usr/src/wordpress --allow-root; \
		chown -R www-data:www-data /usr/src/wordpress; \
	fi; \
	a2enmod rewrite expires headers remoteip; \
	{ \
		echo 'upload_max_filesize = 64M'; \
		echo 'post_max_size = 64M'; \
		echo 'memory_limit = 512M'; \
		echo 'max_execution_time = 120'; \
		echo 'log_errors = On'; \
		echo 'display_errors = Off'; \
		echo 'error_reporting = E_ALL'; \
	} > /usr/local/etc/php/conf.d/zz-sam-matrix.ini; \
	{ \
		echo '# Traffic Guard reads only REMOTE_ADDR. The browser reaches this'; \
		echo '# container through the Docker gateway (a private address, which'; \
		echo '# Traffic Guard never rate-limits), so the harness sends a public'; \
		echo '# documentation-range address in X-Forwarded-For and mod_remoteip'; \
		echo '# puts it into REMOTE_ADDR -- the same as production behind a CDN.'; \
		echo 'RemoteIPHeader X-Forwarded-For'; \
		echo 'RemoteIPInternalProxy 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16'; \
	} > /etc/apache2/conf-available/sam-matrix-remoteip.conf; \
	a2enconf sam-matrix-remoteip

COPY --chmod=0755 harness-entrypoint.sh /usr/local/bin/harness-entrypoint.sh

ENTRYPOINT ["harness-entrypoint.sh"]
CMD ["apache2-foreground"]
