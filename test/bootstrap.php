<?php
/**
 * PHPUnit bootstrap file for Security Automation Manager unit tests.
 *
 * Defines plugin constants and stubs for WordPress globals and functions so
 * the plugin classes can be loaded and exercised without a WordPress install.
 *
 * Only the functions actually called by the classes under test are stubbed.
 * Add stubs here as new test files require them.
 */

declare( strict_types=1 );

// ── Plugin constants ──────────────────────────────────────────────────────────
define( 'ABSPATH',               __DIR__ . '/' );
define( 'WP_CONTENT_DIR',        __DIR__ . '/wp-content' );
define( 'WPINC',                 'wp-includes' );
define( 'WP_SAM_VERSION',        '2.4.30' );
define( 'WP_SAM_DB_VERSION',     '10' );
define( 'WP_SAM_FILE',           dirname( __DIR__ ) . '/security-automation-manager.php' );
define( 'WP_SAM_DIR',            dirname( __DIR__ ) . '/' );
define( 'WP_SAM_URL',            'https://example.com/wp-content/plugins/security-automation-manager/' );
define( 'WP_SAM_PLUGIN_BASENAME', 'security-automation-manager/security-automation-manager.php' );
define( 'WP_SAM_DISTRIBUTION_CHANNEL', 'wordpress-org' );
define( 'WP_SAM_UPDATE_MANIFEST_URL', 'https://vcns.github.io/wp-updates/security-automation-manager/update.json' );
define( 'HOUR_IN_SECONDS',       3600 );
define( 'DAY_IN_SECONDS',        86400 );
define( 'KB_IN_BYTES',           1024 );
define( 'MB_IN_BYTES',           1024 * 1024 );
if ( ! defined( 'DNS_TXT' ) ) {
	define( 'DNS_TXT', 16 );
}
define( 'ARRAY_A',               'ARRAY_A' );
define( 'ARRAY_N',               'ARRAY_N' );
define( 'OBJECT',                'OBJECT' );

// ── PSR-4 autoloader (mirrors security-automation-manager.php) ─────────────────────────
spl_autoload_register( static function ( string $class ): void {
	$prefix = 'WP_SAM\\';
	if ( strncmp( $prefix, $class, strlen( $prefix ) ) !== 0 ) {
		return;
	}
	$relative = substr( $class, strlen( $prefix ) );
	$parts    = explode( '\\', $relative );
	$filename = 'class-' . strtolower( str_replace( '_', '-', (string) array_pop( $parts ) ) ) . '.php';
	$subdir   = ! empty( $parts ) ? strtolower( implode( '/', $parts ) ) . '/' : '';
	$file     = WP_SAM_DIR . 'includes/' . $subdir . $filename;
	if ( ! is_readable( $file ) ) {
		$file = WP_SAM_DIR . 'offline/' . $subdir . $filename;
	}
	if ( is_readable( $file ) ) {
		require_once $file;
	} else {
		trigger_error( "WP_SAM test autoloader: cannot resolve {$class}", E_USER_NOTICE );
	}
} );

// ── WordPress function stubs ──────────────────────────────────────────────────
// These are minimal implementations that satisfy the function signatures
// called by the classes under test. They do not replicate WordPress behaviour
// beyond what is needed for the assertions in the test suite.

if ( ! function_exists( 'current_time' ) ) {
	function current_time( string $type, bool $gmt = false ): string {
		return gmdate( 'Y-m-d H:i:s' );
	}
}

if ( ! function_exists( 'get_option' ) ) {
	function get_option( string $option, mixed $default = false ): mixed {
		return $GLOBALS['_wp_options'][ $option ] ?? $default;
	}
}

if ( ! function_exists( 'status_header' ) ) {
	function status_header( int $code ): void {
		$GLOBALS['_wp_status_header_calls'][] = $code;
	}
}

if ( ! function_exists( 'update_option' ) ) {
	function update_option( string $option, mixed $value, bool|string $autoload = true ): bool {
		$GLOBALS['_wp_options'][ $option ] = $value;
		return true;
	}
}

if ( ! function_exists( 'add_option' ) ) {
	function add_option( string $option, mixed $value = '', string $deprecated = '', bool $autoload = true ): bool {
		if ( ! isset( $GLOBALS['_wp_options'][ $option ] ) ) {
			$GLOBALS['_wp_options'][ $option ] = $value;
			return true;
		}
		return false;
	}
}

if ( ! function_exists( 'delete_option' ) ) {
	function delete_option( string $option ): bool {
		unset( $GLOBALS['_wp_options'][ $option ] );
		return true;
	}
}

if ( ! function_exists( 'is_user_logged_in' ) ) {
	function is_user_logged_in(): bool {
		return $GLOBALS['_wp_is_user_logged_in'] ?? false;
	}
}

if ( ! function_exists( 'get_current_user_id' ) ) {
	function get_current_user_id(): int {
		return $GLOBALS['_wp_current_user_id'] ?? 0;
	}
}

if ( ! function_exists( 'get_transient' ) ) {
	function get_transient( string $transient ): mixed {
		return $GLOBALS['_wp_transients'][ $transient ] ?? false;
	}
}

if ( ! function_exists( 'set_transient' ) ) {
	function set_transient( string $transient, mixed $value, int $expiration = 0 ): bool {
		$GLOBALS['_wp_transients'][ $transient ] = $value;
		return true;
	}
}

if ( ! function_exists( 'delete_transient' ) ) {
	function delete_transient( string $transient ): bool {
		unset( $GLOBALS['_wp_transients'][ $transient ] );
		return true;
	}
}

if ( ! function_exists( 'delete_site_transient' ) ) {
	function delete_site_transient( string $transient ): bool {
		unset( $GLOBALS['_wp_transients'][ $transient ] );
		return true;
	}
}

if ( ! function_exists( 'sanitize_text_field' ) ) {
	function sanitize_text_field( string $str ): string {
		return trim( strip_tags( $str ) );
	}
}

if ( ! function_exists( 'sanitize_textarea_field' ) ) {
	function sanitize_textarea_field( string $str ): string {
		return trim( strip_tags( $str ) );
	}
}

if ( ! function_exists( 'esc_url_raw' ) ) {
	function esc_url_raw( string $url ): string {
		return filter_var( $url, FILTER_SANITIZE_URL ) ?: '';
	}
}

if ( ! function_exists( 'esc_url' ) ) {
	function esc_url( string $url ): string {
		return esc_url_raw( $url );
	}
}

if ( ! function_exists( 'esc_attr' ) ) {
	function esc_attr( string $text ): string {
		return htmlspecialchars( $text, ENT_QUOTES, 'UTF-8' );
	}
}

if ( ! function_exists( 'esc_html' ) ) {
	function esc_html( string $text ): string {
		return htmlspecialchars( $text, ENT_QUOTES, 'UTF-8' );
	}
}

if ( ! function_exists( 'wp_kses_post' ) ) {
	// Real wp_kses_post() strips to an allowed-tags subset; admin views only
	// ever pass their own hardcoded intro/warning HTML through it, so an
	// identity stub is sufficient here -- tests care whether the view
	// renders without fataling, not about tag-stripping behaviour.
	function wp_kses_post( string $html ): string {
		return $html;
	}
}

if ( ! function_exists( '__' ) ) {
	function __( string $text, string $domain = 'default' ): string {
		return $text;
	}
}

if ( ! function_exists( 'esc_html__' ) ) {
	function esc_html__( string $text, string $domain = 'default' ): string {
		return esc_html( $text );
	}
}

if ( ! function_exists( '_e' ) ) {
	function _e( string $text, string $domain = 'default' ): void {
		echo __( $text, $domain );
	}
}

if ( ! function_exists( 'esc_html_e' ) ) {
	function esc_html_e( string $text, string $domain = 'default' ): void {
		echo esc_html__( $text, $domain );
	}
}

if ( ! function_exists( 'esc_attr_e' ) ) {
	function esc_attr_e( string $text, string $domain = 'default' ): void {
		echo esc_attr( __( $text, $domain ) );
	}
}

if ( ! function_exists( 'wp_json_encode' ) ) {
	function wp_json_encode( mixed $data, int $options = 0, int $depth = 512 ): string|false {
		return json_encode( $data, $options, $depth );
	}
}

if ( ! function_exists( 'wp_parse_url' ) ) {
	function wp_parse_url( string $url, int $component = -1 ): mixed {
		return parse_url( $url, $component );
	}
}

if ( ! function_exists( 'add_query_arg' ) ) {
	/**
	 * Minimal stub covering this codebase's only call shape: add_query_arg( array $args, string $url ).
	 */
	function add_query_arg( mixed ...$args ): string {
		$params = is_array( $args[0] ?? null ) ? $args[0] : array( $args[0] => $args[1] ?? '' );
		$url    = is_array( $args[0] ?? null ) ? (string) ( $args[1] ?? '' ) : (string) ( $args[2] ?? '' );

		$parts = wp_parse_url( $url );
		$query = array();
		if ( ! empty( $parts['query'] ) ) {
			parse_str( (string) $parts['query'], $query );
		}

		foreach ( $params as $key => $value ) {
			if ( null === $value ) {
				unset( $query[ $key ] );
			} else {
				$query[ $key ] = $value;
			}
		}

		$base = ( $parts['scheme'] ?? '' ) !== '' ? $parts['scheme'] . '://' . ( $parts['host'] ?? '' ) . ( $parts['path'] ?? '' ) : (string) ( $parts['path'] ?? '' );
		$qs   = http_build_query( $query, '', '&' );

		return $base . ( '' !== $qs ? '?' . $qs : '' );
	}
}

if ( ! function_exists( 'selected' ) ) {
	function selected( mixed $a, mixed $b = true, bool $echo = true ): string {
		$result = ( (string) $a === (string) $b ) ? " selected='selected'" : '';
		if ( $echo ) {
			echo $result; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- test stub.
		}
		return $result;
	}
}

if ( ! function_exists( 'checked' ) ) {
	function checked( mixed $a, mixed $b = true, bool $echo = true ): string {
		$result = ( (string) $a === (string) $b ) ? " checked='checked'" : '';
		if ( $echo ) {
			echo $result; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- test stub.
		}
		return $result;
	}
}

if ( ! function_exists( 'disabled' ) ) {
	function disabled( mixed $a, mixed $b = true, bool $echo = true ): string {
		$result = ( (string) $a === (string) $b ) ? " disabled='disabled'" : '';
		if ( $echo ) {
			echo $result; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- test stub.
		}
		return $result;
	}
}

if ( ! function_exists( 'submit_button' ) ) {
	function submit_button( string $text = 'Save Changes', string $type = 'primary', string $name = 'submit', bool $wrap = true, mixed $other_attributes = null ): void {
		printf(
			'<input type="submit" name="%s" class="button button-%s" value="%s">',
			esc_attr( $name ),
			esc_attr( $type ),
			esc_attr( $text )
		);
	}
}

if ( ! function_exists( 'wp_unslash' ) ) {
	function wp_unslash( mixed $value ): mixed {
		return is_string( $value ) ? stripslashes( $value ) : $value;
	}
}

if ( ! function_exists( 'wp_remote_get' ) ) {
	function wp_remote_get( string $url, array $args = [] ): array|WP_Error {
		$GLOBALS['_wp_remote_get_requests'][] = array(
			'url'  => $url,
			'args' => $args,
		);
		$GLOBALS['_wp_remote_all_requests'][] = array(
			'transport' => 'get',
			'url'       => $url,
			'args'      => $args,
		);
		if ( ! empty( $GLOBALS['_wp_remote_get_response_queue'] ) && is_array( $GLOBALS['_wp_remote_get_response_queue'] ) ) {
			return array_shift( $GLOBALS['_wp_remote_get_response_queue'] );
		}
		return $GLOBALS['_wp_remote_get_response'] ?? [ 'response' => [ 'code' => 200 ], 'body' => '' ];
	}
}

if ( ! function_exists( 'wp_remote_post' ) ) {
	function wp_remote_post( string $url, array $args = [] ): array|WP_Error {
		$GLOBALS['_wp_remote_post_requests'][] = array(
			'url'  => $url,
			'args' => $args,
		);
		$GLOBALS['_wp_remote_all_requests'][] = array(
			'transport' => 'post',
			'url'       => $url,
			'args'      => $args,
		);
		if ( ! empty( $GLOBALS['_wp_remote_post_response_queue'] ) && is_array( $GLOBALS['_wp_remote_post_response_queue'] ) ) {
			return array_shift( $GLOBALS['_wp_remote_post_response_queue'] );
		}
		return $GLOBALS['_wp_remote_post_response'] ?? [ 'response' => [ 'code' => 200 ], 'body' => '' ];
	}
}

if ( ! function_exists( 'download_url' ) ) {
	function download_url( string $url, int $timeout = 300 ): string|WP_Error {
		$GLOBALS['_wp_download_url_requests'][] = array(
			'url'     => $url,
			'timeout' => $timeout,
		);
		return $GLOBALS['_wp_download_url_response'] ?? '';
	}
}

if ( ! function_exists( 'wp_delete_file' ) ) {
	function wp_delete_file( string $file ): void {
		$GLOBALS['_wp_deleted_files'][] = $file;
		if ( is_file( $file ) ) {
			unlink( $file );
		}
	}
}

if ( ! function_exists( 'wp_mkdir_p' ) ) {
	function wp_mkdir_p( string $target ): bool {
		if ( is_dir( $target ) ) {
			return true;
		}
		// @-suppressed: a path occupied by a file (not a directory) is a real,
		// intentionally-exercised test scenario (see DeployerTest's
		// "directory creation failure" case) -- mkdir()'s native warning for
		// that case is expected noise, not a stub bug, and WordPress's real
		// wp_mkdir_p() would emit the same warning in the same situation.
		return @mkdir( $target, 0777, true ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_mkdir, WordPress.PHP.NoSilencedErrors.Discouraged -- test stub.
	}
}

if ( ! function_exists( 'apply_filters' ) ) {
	/**
	 * Actually invokes every add_filter()-registered callback for $hook, in
	 * priority order, threading $value through each in turn -- matching
	 * real WordPress. add_filter() and add_action() share the same
	 * $GLOBALS['_wp_actions'] registration array (see add_filter()'s own
	 * stub below), so this reads from there too.
	 */
	function apply_filters( string $hook, mixed $value, mixed ...$args ): mixed {
		$registrations = $GLOBALS['_wp_actions'][ $hook ] ?? [];
		usort( $registrations, static fn( array $a, array $b ): int => $a[1] <=> $b[1] );

		foreach ( $registrations as [ $callback, $priority, $accepted_args ] ) {
			$call_args = array_slice( [ $value, ...$args ], 0, max( 1, $accepted_args ) );
			$value     = $callback( ...$call_args );
		}

		return $value;
	}
}

if ( ! function_exists( 'wp_generate_uuid4' ) ) {
	function wp_generate_uuid4(): string {
		return $GLOBALS['_wp_generate_uuid4_response'] ?? 'fixture-0000-0000-0000-000000000000';
	}
}

if ( ! function_exists( 'wp_rand' ) ) {
	function wp_rand( int $min = 0, int $max = 0 ): int {
		return random_int( $min, max( $min, $max ) ?: PHP_INT_MAX );
	}
}

if ( ! function_exists( 'wp_salt' ) ) {
	function wp_salt( string $scheme = 'auth' ): string {
		return 'test-salt-' . $scheme;
	}
}

if ( ! function_exists( 'wp_tempnam' ) ) {
	function wp_tempnam( string $filename = '' ): string {
		return (string) tempnam( sys_get_temp_dir(), '' !== $filename ? $filename : 'wp-test' );
	}
}

if ( ! function_exists( 'wp_remote_head' ) ) {
	function wp_remote_head( string $url, array $args = [] ): array|WP_Error {
		$GLOBALS['_wp_remote_head_requests'][] = array(
			'url'  => $url,
			'args' => $args,
		);
		$GLOBALS['_wp_remote_all_requests'][] = array(
			'transport' => 'head',
			'url'       => $url,
			'args'      => $args,
		);
		if ( ! empty( $GLOBALS['_wp_remote_head_response_queue'] ) && is_array( $GLOBALS['_wp_remote_head_response_queue'] ) ) {
			return array_shift( $GLOBALS['_wp_remote_head_response_queue'] );
		}
		return $GLOBALS['_wp_remote_head_response'] ?? [ 'response' => [ 'code' => 200 ], 'headers' => [] ];
	}
}

if ( ! function_exists( 'wp_remote_request' ) ) {
	// The general-purpose HTTP entry point: $args['method'] carries the verb
	// (GET/POST/PUT/DELETE/...). This is what Dns_Provider::request()/
	// request_raw() call for every JSON- and raw-bodied provider driver (37
	// of 41) -- previously entirely unstubbed, so no provider using the
	// shared base-class helper could be unit-tested at all before Phase 6B.
	function wp_remote_request( string $url, array $args = [] ): array|WP_Error {
		$GLOBALS['_wp_remote_request_requests'][] = array(
			'url'  => $url,
			'args' => $args,
		);
		$GLOBALS['_wp_remote_all_requests'][] = array(
			'transport' => 'request',
			'url'       => $url,
			'args'      => $args,
		);
		if ( ! empty( $GLOBALS['_wp_remote_request_response_queue'] ) && is_array( $GLOBALS['_wp_remote_request_response_queue'] ) ) {
			return array_shift( $GLOBALS['_wp_remote_request_response_queue'] );
		}
		return $GLOBALS['_wp_remote_request_response'] ?? [ 'response' => [ 'code' => 200 ], 'body' => '' ];
	}
}

if ( ! function_exists( 'wp_remote_retrieve_headers' ) ) {
	function wp_remote_retrieve_headers( array|WP_Error $response ): mixed {
		if ( $response instanceof WP_Error ) {
			return [];
		}

		return $response['headers'] ?? [];
	}
}

if ( ! function_exists( 'wp_remote_retrieve_header' ) ) {
	function wp_remote_retrieve_header( array|WP_Error $response, string $header ): mixed {
		if ( $response instanceof WP_Error ) {
			return '';
		}

		$headers = $response['headers'] ?? [];
		// A real WP_HTTP_Requests_Response's headers object is case-insensitive
		// on lookup; the stub's fixture arrays are plain assoc arrays, so match
		// case-insensitively here to mirror that behaviour.
		foreach ( $headers as $key => $value ) {
			if ( 0 === strcasecmp( (string) $key, $header ) ) {
				return $value;
			}
		}

		return '';
	}
}

if ( ! function_exists( 'wp_remote_retrieve_response_code' ) ) {
	function wp_remote_retrieve_response_code( array|WP_Error $response ): int|string {
		return $response['response']['code'] ?? 0;
	}
}

if ( ! function_exists( 'wp_remote_retrieve_body' ) ) {
	function wp_remote_retrieve_body( array|WP_Error $response ): string {
		return $response['body'] ?? '';
	}
}

if ( ! function_exists( 'is_wp_error' ) ) {
	function is_wp_error( mixed $thing ): bool {
		return $thing instanceof WP_Error;
	}
}

if ( ! function_exists( 'rest_url' ) ) {
	/**
	 * Models the handful of real WordPress inputs get_rest_url() actually
	 * varies its output on -- a plain-vs-pretty permalink structure, the
	 * filterable REST URL prefix (default "wp-json"), and a multisite
	 * subsite path -- via global flags, following this file's existing
	 * pattern for configurable stub behaviour (see wp_test_reset_globals()
	 * for defaults). Deliberately does NOT model an "unsafe before init"
	 * failure mode: WordPress's own reference docs for rest_url()/
	 * get_rest_url() document no such requirement, and Reporting_Endpoint::
	 * url() no longer special-cases it -- see that class's docblock.
	 */
	function rest_url( string $path = '' ): string {
		$prefix       = $GLOBALS['_wp_rest_url_prefix'] ?? 'wp-json';
		$subsite_path = $GLOBALS['_wp_multisite_subsite_path'] ?? '';
		$trimmed_path = ltrim( $path, '/' );

		if ( ! empty( $GLOBALS['_wp_rest_url_plain_permalinks'] ) ) {
			return 'https://example.com' . $subsite_path . '/?rest_route=/' . $trimmed_path;
		}

		return 'https://example.com' . $subsite_path . '/' . $prefix . '/' . $trimmed_path;
	}
}

if ( ! function_exists( 'get_site_url' ) ) {
	function get_site_url( int $blog_id = 0, string $path = '', string $scheme = '' ): string {
		return 'https://example.com';
	}
}

if ( ! function_exists( 'home_url' ) ) {
	function home_url( string $path = '', string $scheme = '' ): string {
		return 'https://example.com' . ( '' !== $path ? '/' . ltrim( $path, '/' ) : '' );
	}
}

if ( ! function_exists( 'get_home_url' ) ) {
	function get_home_url( int $blog_id = 0, string $path = '', string $scheme = '' ): string {
		return home_url( $path, $scheme );
	}
}

if ( ! function_exists( 'site_url' ) ) {
	function site_url( string $path = '', string $scheme = '' ): string {
		return home_url( $path, $scheme );
	}
}

if ( ! function_exists( 'admin_url' ) ) {
	function admin_url( string $path = '', string $scheme = 'admin' ): string {
		return 'https://example.com/wp-admin/' . ltrim( $path, '/' );
	}
}

if ( ! function_exists( 'content_url' ) ) {
	function content_url( string $path = '' ): string {
		return 'https://example.com/wp-content' . ( '' !== $path ? '/' . ltrim( $path, '/' ) : '' );
	}
}

if ( ! function_exists( 'includes_url' ) ) {
	function includes_url( string $path = '', string $scheme = '' ): string {
		return 'https://example.com/wp-includes/' . ltrim( $path, '/' );
	}
}

if ( ! function_exists( 'plugin_basename' ) ) {
	function plugin_basename( string $file ): string {
		return 'security-automation-manager/security-automation-manager.php';
	}
}

if ( ! function_exists( 'get_bloginfo' ) ) {
	function get_bloginfo( string $show = '' ): string {
		if ( 'version' === $show ) {
			return '7.0';
		}

		if ( 'url' === $show ) {
			return 'https://example.com';
		}

		return '';
	}
}

if ( ! function_exists( 'is_admin' ) ) {
	function is_admin(): bool {
		return $GLOBALS['_wp_is_admin'] ?? false;
	}
}

if ( ! function_exists( 'is_ssl' ) ) {
	function is_ssl(): bool {
		return $GLOBALS['_wp_is_ssl'] ?? false;
	}
}

if ( ! function_exists( 'wp_doing_cron' ) ) {
	function wp_doing_cron(): bool {
		return $GLOBALS['_wp_doing_cron'] ?? false;
	}
}

if ( ! function_exists( 'add_action' ) ) {
	function add_action( string $hook, callable $callback, int $priority = 10, int $accepted_args = 1 ): bool {
		$GLOBALS['_wp_actions'][ $hook ][] = [ $callback, $priority, $accepted_args ];
		return true;
	}
}

if ( ! function_exists( 'add_filter' ) ) {
	function add_filter( string $hook, callable $callback, int $priority = 10, int $accepted_args = 1 ): bool {
		return add_action( $hook, $callback, $priority, $accepted_args );
	}
}

if ( ! function_exists( 'did_action' ) ) {
	function did_action( string $hook ): int {
		return (int) ( $GLOBALS['_wp_did_actions'][ $hook ] ?? 0 );
	}
}

if ( ! function_exists( 'do_action' ) ) {
	/**
	 * Actually invokes every add_action()-registered callback for $hook, in
	 * priority order -- matching real WordPress. Also increments
	 * did_action()'s counter, matching real WordPress there too.
	 */
	function do_action( string $hook, mixed ...$args ): void {
		$GLOBALS['_wp_did_actions'][ $hook ] = (int) ( $GLOBALS['_wp_did_actions'][ $hook ] ?? 0 ) + 1;

		$registrations = $GLOBALS['_wp_actions'][ $hook ] ?? [];
		usort( $registrations, static fn( array $a, array $b ): int => $a[1] <=> $b[1] );

		foreach ( $registrations as [ $callback, $priority, $accepted_args ] ) {
			$callback( ...array_slice( $args, 0, $accepted_args ) );
		}
	}
}

if ( ! function_exists( 'headers_sent' ) ) {
	// Intentionally not overriding the native headers_sent() -- it is a PHP
	// built-in and behaves correctly in a CLI test context (always returns false).
}

if ( ! function_exists( 'hash_equals' ) ) {
	// Native PHP function; already available in PHP 8.1+. Stub only if absent.
}

// ── WP_Error / REST stubs ─────────────────────────────────────────────────────
if ( ! class_exists( 'WP_REST_Request' ) ) {
	class WP_REST_Request implements ArrayAccess {
		private array $params = [];

		public function __construct( public string $method = 'POST', public string $route = '' ) {}

		public function get_body(): string {
			return $GLOBALS['_wp_rest_body'] ?? '';
		}

		public function get_header( string $name ): ?string {
			return $GLOBALS['_wp_rest_headers'][ $name ] ?? null;
		}

		public function get_content_type(): ?array {
			$raw = $GLOBALS['_wp_rest_headers']['content-type'] ?? null;
			if ( null === $raw ) {
				return null;
			}
			$parts = explode( ';', $raw, 2 );
			return array(
				'value'      => trim( $parts[0] ),
				'parameters' => isset( $parts[1] ) ? array( 'params' => trim( $parts[1] ) ) : array(),
			);
		}

		public function set_param( string $key, mixed $value ): void {
			$this->params[ $key ] = $value;
		}

		public function offsetExists( mixed $offset ): bool {
			return isset( $this->params[ $offset ] );
		}

		public function offsetGet( mixed $offset ): mixed {
			return $this->params[ $offset ] ?? null;
		}

		public function offsetSet( mixed $offset, mixed $value ): void {
			$this->params[ $offset ] = $value;
		}

		public function offsetUnset( mixed $offset ): void {
			unset( $this->params[ $offset ] );
		}
	}
}

if ( ! class_exists( 'WP_REST_Server' ) ) {
	class WP_REST_Server {
		public const READABLE = 'GET';
		public const CREATABLE = 'POST';
		public const EDITABLE = 'POST, PUT, PATCH';
	}
}

if ( ! class_exists( 'WP_REST_Response' ) ) {
	class WP_REST_Response {
		public function __construct( public mixed $data = null, public int $status = 200 ) {}

		public function get_status(): int {
			return $this->status;
		}

		public function get_data(): mixed {
			return $this->data;
		}
	}
}

if ( ! class_exists( 'WP_Error' ) ) {
	class WP_Error {
		private string $code;
		private string $message;

		public function __construct( string $code = '', string $message = '' ) {
			$this->code    = $code;
			$this->message = $message;
		}

		public function get_error_code(): string {
			return $this->code;
		}

		public function get_error_message(): string {
			return $this->message;
		}
	}
}

// ── wpdb stub ─────────────────────────────────────────────────────────────────
// Minimal implementation that returns configurable values from globals.
// Tests set $GLOBALS['_wpdb_*'] before calling the code under test.
if ( ! class_exists( 'wpdb' ) ) {
	// Minimal stand-in for WordPress core's wpdb class so type-hinted `\wpdb $wpdb`
	// parameters accept wpdb_stub instances under PHP's type system.
	class wpdb {}
}

if ( ! class_exists( 'wpdb_stub' ) ) {
	class wpdb_stub extends wpdb {
		public string  $prefix     = 'wp_';
		public ?string $last_error = null;
		public int     $rows_affected = 0;
		public int     $insert_id      = 0;

		public function prepare( string $query, mixed ...$args ): string {
			$i = 0;
			return (string) preg_replace_callback(
				'/%%|%(s|d)/',
				static function ( array $m ) use ( &$i, $args ): string {
					if ( '%%' === $m[0] ) {
						return '%';
					}
					$val = $args[ $i++ ] ?? '';
					return 's' === $m[1]
						? "'" . addslashes( (string) $val ) . "'"
						: (string) (int) $val;
				},
				$query
			);
		}

		public function get_var( string $query ): mixed {
			if ( ! empty( $GLOBALS['_wpdb_get_var_queue'] ) && is_array( $GLOBALS['_wpdb_get_var_queue'] ) ) {
				return array_shift( $GLOBALS['_wpdb_get_var_queue'] );
			}
			return $GLOBALS['_wpdb_get_var'] ?? null;
		}

		public function get_row( string $query, string $output = 'ARRAY_A' ): mixed {
			if ( ! empty( $GLOBALS['_wpdb_get_row_queue'] ) && is_array( $GLOBALS['_wpdb_get_row_queue'] ) ) {
				return array_shift( $GLOBALS['_wpdb_get_row_queue'] );
			}
			return $GLOBALS['_wpdb_get_row'] ?? null;
		}

		public function get_results( string $query, string $output = 'ARRAY_A' ): array {
			$GLOBALS['_wpdb_last_get_results_query'] = $query;
			if ( ! empty( $GLOBALS['_wpdb_get_results_queue'] ) && is_array( $GLOBALS['_wpdb_get_results_queue'] ) ) {
				return array_shift( $GLOBALS['_wpdb_get_results_queue'] );
			}
			return $GLOBALS['_wpdb_get_results'] ?? [];
		}

		public function get_col( string $query ): array {
			return $GLOBALS['_wpdb_get_col'] ?? [];
		}

		public function esc_like( string $text ): string {
			return addcslashes( $text, '_%\\' );
		}

		public function query( string $sql ): int|false {
			$GLOBALS['_wpdb_last_operation'] = 'query';
			$GLOBALS['_wpdb_last_query']     = $sql;
			$GLOBALS['_wpdb_queries'][]      = $sql;
			$result                          = $GLOBALS['_wpdb_query_result'] ?? 1;
			$this->rows_affected             = false === $result ? 0 : (int) $result;
			return $result;
		}

		public function insert( string $table, array $data, array $format = [] ): int|false {
			$GLOBALS['_wpdb_last_operation'] = 'insert';
			$this->rows_affected            = 1;
			++$this->insert_id;
			$GLOBALS['_wpdb_inserted_rows'][] = array(
				'table'  => $table,
				'data'   => $data,
				'format' => $format,
			);
			return $GLOBALS['_wpdb_insert_result'] ?? 1;
		}

		public function update( string $table, array $data, array $where, array $format = [], array $where_format = [] ): int|false {
			$GLOBALS['_wpdb_last_operation'] = 'update';
			$result                         = $GLOBALS['_wpdb_update_result'] ?? 0;
			$this->rows_affected            = false === $result ? 0 : (int) $result;
			$GLOBALS['_wpdb_updated_rows'][] = array(
				'table'        => $table,
				'data'         => $data,
				'where'        => $where,
				'format'       => $format,
				'where_format' => $where_format,
			);
			return $result;
		}

		public function get_charset_collate(): string {
			return 'DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci';
		}
	}
}

// ── WordPress function stubs (activation / cron) ──────────────────────────────

if ( ! function_exists( 'wp_next_scheduled' ) ) {
	function wp_next_scheduled( string $hook, array $args = [] ): int|false {
		return $GLOBALS['_wp_cron'][ $hook ] ?? false;
	}
}

if ( ! function_exists( 'wp_schedule_event' ) ) {
	function wp_schedule_event( int $timestamp, string $recurrence, string $hook ): bool {
		$GLOBALS['_wp_cron'][ $hook ] = $timestamp;
		return true;
	}
}

if ( ! function_exists( 'wp_schedule_single_event' ) ) {
	function wp_schedule_single_event( int $timestamp, string $hook ): bool {
		$GLOBALS['_wp_cron'][ $hook ] = $timestamp;
		return true;
	}
}

if ( ! function_exists( 'spawn_cron' ) ) {
	function spawn_cron(): bool {
		++$GLOBALS['_wp_spawn_cron_calls'];
		return true;
	}
}

if ( ! function_exists( 'wp_unschedule_hook' ) ) {
	function wp_unschedule_hook( string $hook ): int {
		unset( $GLOBALS['_wp_cron'][ $hook ] );
		return 1;
	}
}

if ( ! function_exists( 'wp_clear_scheduled_hook' ) ) {
	function wp_clear_scheduled_hook( string $hook ): int {
		unset( $GLOBALS['_wp_cron'][ $hook ] );
		return 1;
	}
}

if ( ! function_exists( 'dbDelta' ) ) {
	function dbDelta( string $queries = '' ): array {
		$GLOBALS['_dbdelta_queries'][] = $queries;
		return [];
	}
}

if ( ! function_exists( 'current_user_can' ) ) {
	function current_user_can( string $capability ): bool {
		return $GLOBALS['_wp_current_user_can'][ $capability ] ?? false;
	}
}

// ── Global state reset helper ─────────────────────────────────────────────────
// Call this in setUp() to start each test with a clean slate.
function wp_test_reset_globals(): void {
	$GLOBALS['_wp_options']              = [];
	$GLOBALS['_wp_transients']           = [];
	$GLOBALS['_wp_actions']              = [];
	$GLOBALS['_wp_did_actions']          = [];
	$GLOBALS['_wp_rest_url_prefix']            = 'wp-json';
	$GLOBALS['_wp_rest_url_plain_permalinks']  = false;
	$GLOBALS['_wp_multisite_subsite_path']     = '';

	$GLOBALS['_wp_remote_get_response']  = null;
	$GLOBALS['_wp_remote_get_response_queue'] = [];
	$GLOBALS['_wp_remote_get_requests']  = [];
	$GLOBALS['_wp_remote_post_response'] = null;
	$GLOBALS['_wp_remote_post_response_queue'] = [];
	$GLOBALS['_wp_remote_post_requests'] = [];
	$GLOBALS['_wp_download_url_response'] = '';
	$GLOBALS['_wp_download_url_requests'] = [];
	$GLOBALS['_wp_deleted_files']        = [];
	$GLOBALS['_wp_remote_head_response'] = null;
	$GLOBALS['_wp_remote_head_response_queue'] = [];
	$GLOBALS['_wp_remote_head_requests'] = [];
	$GLOBALS['_wp_remote_request_response'] = null;
	$GLOBALS['_wp_remote_request_response_queue'] = [];
	$GLOBALS['_wp_remote_request_requests'] = [];
	$GLOBALS['_wp_remote_all_requests']  = [];
	$GLOBALS['_wp_spawn_cron_calls']     = 0;
	$GLOBALS['_wp_status_header_calls']  = [];
	$GLOBALS['_wp_is_admin']             = false;
	$GLOBALS['_wp_is_ssl']               = false;
	$GLOBALS['_wp_doing_cron']           = false;
	$GLOBALS['_wp_cron']                 = [];
	$GLOBALS['_wp_current_user_can']     = [];
	$GLOBALS['_wpdb_get_var']            = null;
	$GLOBALS['_wpdb_get_row']            = null;
	$GLOBALS['_wpdb_get_var_queue']      = [];
	$GLOBALS['_wpdb_get_row_queue']      = [];
	$GLOBALS['_wpdb_get_results']        = [];
	$GLOBALS['_wpdb_get_results_queue']  = [];
	$GLOBALS['_wpdb_last_get_results_query'] = null;
	$GLOBALS['_wpdb_get_col']            = [];
	$GLOBALS['_wpdb_insert_result']      = 1;
	$GLOBALS['_wpdb_update_result']      = 0;
	$GLOBALS['wpdb']                     = new wpdb_stub();
	$GLOBALS['_wp_sam_test_nonce']       = '';
	$GLOBALS['_wp_rest_body']            = '';
	$GLOBALS['_wp_rest_headers']         = [];
	$GLOBALS['_wpdb_query_result']       = 1;
	$GLOBALS['_wpdb_last_operation']     = null;
	$GLOBALS['_wpdb_last_query']         = null;
	$GLOBALS['_wpdb_queries']            = [];
	$GLOBALS['_wpdb_inserted_rows']      = [];
	$GLOBALS['_wpdb_updated_rows']       = [];
	$GLOBALS['_dbdelta_queries']         = [];
	unset( $_SERVER['REQUEST_URI'] );
	unset( $_SERVER['HTTP_HOST'] );
	unset( $_SERVER['HTTP_X_FORWARDED_HOST'] );
	unset( $_SERVER['HTTP_X_WP_SAM_PROBE'] );
}

// Initialise globals so classes loaded at parse time do not hit undefined array errors.
wp_test_reset_globals();

// ── Test stubs ────────────────────────────────────────────────────────────────
// Load namespace-scoped stubs before any plugin class that might define the
// real counterpart. Order matters: stubs must come first.
require_once __DIR__ . '/unit/NonceBridge.php';

// Shared abstract test-case base classes must be loaded before any concrete
// test file that extends them -- PHPUnit's directory-based discovery does
// not guarantee one test file is required before another, so a concrete
// subclass sitting alphabetically before its abstract parent (e.g.
// ProviderContractCloudflareTest.php before Dns_Provider_Contract_TestCase.php)
// fails with "class not found" unless the parent is required explicitly here.
require_once __DIR__ . '/unit/Dns_Provider_Contract_TestCase.php';
