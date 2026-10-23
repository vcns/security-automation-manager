<?php
/**
 * GitHub-channel plugin update integration.
 *
 * This class is only bundled into the GitHub-channel ZIP. WordPress.org
 * distribution packages exclude it and rely on the plugin directory updater.
 */

declare( strict_types=1 );

namespace WP_SAM\Modules;

use WP_Error;
use stdClass;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Github_Update_Checker {

	private const UPDATE_URL          = 'https://vcns.github.io/wp-updates/security-automation-manager/update.json';
	private const UPDATE_HOST         = 'vcns.github.io';
	private const UPDATE_PATH         = '/wp-updates/security-automation-manager/';
	private const CACHE_KEY           = 'wp_sam_github_update_info';
	private const SUCCESS_CACHE_TTL   = 12 * HOUR_IN_SECONDS;
	private const FAILURE_CACHE_TTL   = HOUR_IN_SECONDS;
	private const SLUG                = 'security-automation-manager';
	private const DISABLE_AUTO_UPDATE = 'WP_SAM_DISABLE_AUTO_UPDATE';

	/**
	 * Durable diagnostic state for the Overview page's Updates tab. The manifest
	 * cache above (CACHE_KEY) is a short-lived transient purely for reducing
	 * remote requests -- once it expires, any record of the last check's
	 * outcome disappears with it. This option is written on every relevant
	 * event (manifest check, checksum verification, applied update) and never
	 * expires on its own, so "Last successful check" / "Last failed check" /
	 * "Last update result" stay accurate between requests. No secrets are
	 * ever stored here -- every field is either a timestamp or a short,
	 * fixed-vocabulary status code.
	 */
	public const DIAGNOSTICS_OPTION = 'wp_sam_update_diagnostics';

	/**
	 * Registers the update, plugin information, download verification and auto-update hooks.
	 *
	 * @return void
	 */
	public function register(): void {
		add_filter( 'pre_set_site_transient_update_plugins', array( $this, 'inject_update' ) );
		add_filter( 'site_transient_update_plugins', array( $this, 'suppress_stale_update_offer' ), 20 );
		add_filter( 'plugins_api', array( $this, 'plugin_info' ), 10, 3 );
		add_filter( 'upgrader_pre_download', array( $this, 'verify_package_download' ), 10, 4 );
		add_action( 'upgrader_process_complete', array( $this, 'after_update' ), 10, 2 );
		add_filter( 'auto_update_plugin', array( $this, 'auto_update_gate' ), 10, 2 );
		add_action( 'delete_site_transient_update_plugins', array( $this, 'clear_remote_cache' ) );
		add_action( 'load-update-core.php', array( $this, 'clear_remote_cache' ) );
	}

	/**
	 * Adds the GitHub release to the update_plugins transient when it is newer than the installed version.
	 *
	 * @param mixed $transient The update_plugins site transient.
	 * @return mixed The transient, with the update offer added when one applies.
	 */
	public function inject_update( mixed $transient ): mixed {
		if ( ! is_object( $transient ) || empty( $transient->checked ) ) {
			return $transient;
		}

		$this->clear_update_entries( $transient );

		$remote = $this->get_remote_info();
		if ( null === $remote ) {
			return $transient;
		}

		$item               = new stdClass();
		$item->id           = self::UPDATE_URL;
		$item->slug         = self::SLUG;
		$item->plugin       = WP_SAM_PLUGIN_BASENAME;
		$item->new_version  = $remote->version;
		$item->url          = $remote->homepage ?? '';
		$item->package      = $remote->download_url ?? '';
		$item->icons        = array();
		$item->banners      = array();
		$item->tested       = $remote->tested ?? '';
		$item->requires_php = $remote->requires_php ?? '';

		if ( version_compare( WP_SAM_VERSION, $remote->version, '<' ) ) {
			$transient->response[ WP_SAM_PLUGIN_BASENAME ] = $item;
		} else {
			$item->package                                  = '';
			$transient->no_update[ WP_SAM_PLUGIN_BASENAME ] = $item;
		}

		return $transient;
	}

	/**
	 * Removes an update offer that is not newer than the installed version.
	 *
	 * @param mixed $transient The update_plugins site transient.
	 * @return mixed The transient without the stale offer.
	 */
	public function suppress_stale_update_offer( mixed $transient ): mixed {
		if ( ! is_object( $transient ) || empty( $transient->response ) || ! is_array( $transient->response ) ) {
			return $transient;
		}

		$offer = $transient->response[ WP_SAM_PLUGIN_BASENAME ] ?? null;
		if ( ! is_object( $offer ) ) {
			return $transient;
		}

		$offered_version = (string) ( $offer->new_version ?? '' );
		if ( '' === $offered_version || version_compare( WP_SAM_VERSION, $offered_version, '<' ) ) {
			return $transient;
		}

		unset( $transient->response[ WP_SAM_PLUGIN_BASENAME ] );

		if ( ! isset( $transient->no_update ) || ! is_array( $transient->no_update ) ) {
			$transient->no_update = array();
		}

		$offer->new_version                             = WP_SAM_VERSION;
		$offer->package                                 = '';
		$transient->no_update[ WP_SAM_PLUGIN_BASENAME ] = $offer;

		return $transient;
	}

	/**
	 * Supplies the plugin details shown in the "View details" modal.
	 *
	 * @param mixed  $result The current plugins_api result.
	 * @param string $action The plugins_api action.
	 * @param object $args   The request arguments, including the plugin slug.
	 * @return mixed The plugin information object, or the unchanged result.
	 */
	public function plugin_info( mixed $result, string $action, object $args ): mixed {
		if ( 'plugin_information' !== $action || self::SLUG !== ( $args->slug ?? '' ) ) {
			return $result;
		}

		$remote = $this->get_remote_info();
		if ( null === $remote ) {
			return $result;
		}

		$info                = new stdClass();
		$info->name          = $remote->name ?? 'Security Automation Manager';
		$info->slug          = self::SLUG;
		$info->version       = $remote->version;
		$info->author        = '<a href="' . esc_url( $remote->author_homepage ?? '' ) . '">'
			. esc_html( $remote->author ?? 'VCNS Tech Ltd' ) . '</a>';
		$info->requires      = $remote->requires ?? '6.4';
		$info->tested        = $remote->tested ?? '';
		$info->requires_php  = $remote->requires_php ?? '8.1';
		$info->last_updated  = $remote->last_updated ?? '';
		$info->download_link = $remote->download_url ?? '';
		$info->sections      = (array) ( $remote->sections ?? new stdClass() );
		$info->icons         = array();
		$info->banners       = array();

		return $info;
	}

	/**
	 * Clears the cached release data and records the outcome after this plugin has been updated.
	 *
	 * @param object $upgrader   The upgrader instance.
	 * @param array  $hook_extra Details of the completed upgrade.
	 * @return void
	 */
	public function after_update( object $upgrader, array $hook_extra ): void {
		if (
			isset( $hook_extra['type'], $hook_extra['action'] )
			&& 'plugin' === $hook_extra['type']
			&& 'update' === $hook_extra['action']
			&& $this->is_plugin_update( $hook_extra )
		) {
			$this->clear_remote_cache();
			delete_site_transient( 'update_plugins' );
			$this->record_applied_update_result( $upgrader );
		}
	}

	/**
	 * Determines whether the just-completed update actually succeeded.
	 * upgrader_process_complete fires regardless of outcome -- $upgrader
	 * doesn't expose a single success/failure flag directly, so this checks
	 * both places WordPress core surfaces a failure: a WP_Error result, and
	 * errors recorded on the upgrader's skin.
	 */
	private function record_applied_update_result( object $upgrader ): void {
		$result = property_exists( $upgrader, 'result' ) ? $upgrader->result : null;
		$failed = is_wp_error( $result );

		if ( ! $failed && isset( $upgrader->skin ) && is_object( $upgrader->skin ) && method_exists( $upgrader->skin, 'get_errors' ) ) {
			$skin_errors = $upgrader->skin->get_errors();
			$failed      = $skin_errors instanceof WP_Error && ! empty( $skin_errors->errors );
		}

		$this->update_diagnostics(
			array(
				'last_applied_at'     => current_time( 'mysql', true ),
				'last_applied_result' => $failed ? 'failure' : 'success',
			)
		);
	}

	/**
	 * Deletes the cached release manifest so the next check fetches a fresh one.
	 *
	 * @return void
	 */
	public function clear_remote_cache(): void {
		delete_transient( self::CACHE_KEY );
	}

	/**
	 * Blocks automatic updates for this plugin when the disable constant is set.
	 *
	 * @param bool|null $update Whether WordPress would auto-update the item.
	 * @param object    $item   The update item.
	 * @return bool|null False when auto-updates are disabled for this plugin, otherwise the incoming value.
	 */
	public function auto_update_gate( ?bool $update, object $item ): ?bool {
		if ( ! isset( $item->plugin ) || WP_SAM_PLUGIN_BASENAME !== $item->plugin ) {
			return $update;
		}

		if ( defined( self::DISABLE_AUTO_UPDATE ) && constant( self::DISABLE_AUTO_UPDATE ) ) {
			return false;
		}

		return $update;
	}

	/**
	 * Downloads the update package and verifies its SHA-256 checksum against the manifest.
	 *
	 * @param mixed  $reply      The download short-circuit value, false to proceed.
	 * @param string $package    URL of the package being downloaded.
	 * @param object $upgrader   The upgrader instance.
	 * @param array  $hook_extra Details of the upgrade.
	 * @return mixed The downloaded file path, a WP_Error when verification fails, or the incoming reply for other packages.
	 */
	public function verify_package_download( mixed $reply, string $package, object $upgrader, array $hook_extra ): mixed {
		unset( $upgrader );

		if ( false !== $reply || ! $this->is_plugin_update( $hook_extra ) ) {
			return $reply;
		}

		$remote = $this->get_remote_info();
		if ( null === $remote || empty( $remote->download_url ) || $package !== $remote->download_url ) {
			return new WP_Error( 'wp_sam_update_metadata_unavailable', 'Security Automation Manager update metadata could not be verified.' );
		}

		if ( empty( $remote->sha256 ) || ! $this->is_valid_sha256( (string) $remote->sha256 ) ) {
			$this->record_checksum_result( 'missing' );
			return new WP_Error( 'wp_sam_update_checksum_missing', 'Security Automation Manager update package checksum is missing or invalid.' );
		}

		if ( ! function_exists( 'download_url' ) ) {
			return new WP_Error( 'wp_sam_update_download_unavailable', 'WordPress package download support is unavailable.' );
		}

		$file = download_url( $package, 300 );
		if ( is_wp_error( $file ) ) {
			return $file;
		}

		$actual = is_string( $file ) && is_readable( $file ) ? hash_file( 'sha256', $file ) : false;
		if ( ! is_string( $actual ) || ! hash_equals( strtolower( (string) $remote->sha256 ), strtolower( $actual ) ) ) {
			if ( is_string( $file ) && is_file( $file ) ) {
				wp_delete_file( $file );
			}

			$this->record_checksum_result( 'mismatch' );
			return new WP_Error( 'wp_sam_update_checksum_mismatch', 'Security Automation Manager update package checksum verification failed.' );
		}

		$this->record_checksum_result( 'verified' );
		return $file;
	}

	/**
	 * Stores the outcome of the latest checksum verification.
	 *
	 * @param string $result Short status code.
	 * @return void
	 */
	private function record_checksum_result( string $result ): void {
		$this->update_diagnostics(
			array(
				'last_checksum_at'     => current_time( 'mysql', true ),
				'last_checksum_result' => $result,
			)
		);
	}

	/**
	 * Fetches and validates the release manifest, caching both successes and failures.
	 *
	 * @return object|null The validated release data, or null when unavailable or invalid.
	 */
	public function get_remote_info(): ?object {
		$cached = get_transient( self::CACHE_KEY );
		if ( is_array( $cached ) ) {
			return $cached['data'] instanceof stdClass ? $cached['data'] : null;
		}

		$response = wp_remote_get(
			defined( 'WP_SAM_UPDATE_MANIFEST_URL' ) ? WP_SAM_UPDATE_MANIFEST_URL : self::UPDATE_URL,
			array(
				'timeout'    => 10,
				'user-agent' => 'WordPress/' . get_bloginfo( 'version' ) . '; CSP-Automation-Manager/' . WP_SAM_VERSION . '; ' . get_bloginfo( 'url' ),
			)
		);

		$now = current_time( 'mysql', true );

		if ( is_wp_error( $response ) || 200 !== (int) wp_remote_retrieve_response_code( $response ) ) {
			set_transient( self::CACHE_KEY, array( 'data' => null ), self::FAILURE_CACHE_TTL );
			$this->update_diagnostics(
				array(
					'last_check_at'         => $now,
					'last_check_result'     => 'http_error',
					'last_check_failure_at' => $now,
				)
			);
			return null;
		}

		$data = json_decode( (string) wp_remote_retrieve_body( $response ) );
		if ( ! is_object( $data ) || ! $this->validate_remote_info( $data ) ) {
			set_transient( self::CACHE_KEY, array( 'data' => null ), self::FAILURE_CACHE_TTL );
			$this->update_diagnostics(
				array(
					'last_check_at'         => $now,
					'last_check_result'     => 'invalid_manifest',
					'last_check_failure_at' => $now,
				)
			);
			return null;
		}

		set_transient( self::CACHE_KEY, array( 'data' => $data ), self::SUCCESS_CACHE_TTL );
		$this->update_diagnostics(
			array(
				'last_check_at'         => $now,
				'last_check_result'     => 'success',
				'last_check_success_at' => $now,
				'available_version'     => (string) $data->version,
			)
		);
		return $data;
	}

	/**
	 * @param array<string,string> $changes
	 */
	private function update_diagnostics( array $changes ): void {
		$current = get_option( self::DIAGNOSTICS_OPTION, array() );
		if ( ! is_array( $current ) ) {
			$current = array();
		}

		update_option( self::DIAGNOSTICS_OPTION, array_merge( $current, $changes ) );
	}

	/**
	 * Removes this plugin from the transient's response and no_update lists.
	 *
	 * @param object $transient The update_plugins site transient, modified in place.
	 * @return void
	 */
	private function clear_update_entries( object $transient ): void {
		foreach ( array( 'response', 'no_update' ) as $property ) {
			if ( ! isset( $transient->{$property} ) ) {
				$transient->{$property} = array();
			}

			if ( is_array( $transient->{$property} ) ) {
				unset( $transient->{$property}[ WP_SAM_PLUGIN_BASENAME ] );
			}
		}
	}

	/**
	 * Checks that the manifest names this plugin, has a valid version, and points at an allowed package URL.
	 *
	 * @param object $data Decoded manifest.
	 * @return bool True when the manifest is acceptable.
	 */
	private function validate_remote_info( object $data ): bool {
		if ( self::SLUG !== (string) ( $data->slug ?? '' ) ) {
			return false;
		}

		if ( empty( $data->version ) || ! $this->is_valid_version( (string) $data->version ) ) {
			return false;
		}

		if ( empty( $data->download_url ) || ! $this->is_allowed_package_url( (string) $data->download_url ) ) {
			return false;
		}

		return ! empty( $data->sha256 ) && $this->is_valid_sha256( (string) $data->sha256 );
	}

	/**
	 * Checks that a version string is in MAJOR.MINOR.PATCH form, with an optional suffix.
	 *
	 * @param string $version Version string.
	 * @return bool True when valid.
	 */
	private function is_valid_version( string $version ): bool {
		return preg_match( '/^\d+\.\d+\.\d+(?:[-+][A-Za-z0-9_.-]+)?$/', $version ) === 1;
	}

	/**
	 * Checks that a package URL is an https .zip on the update host, under the update path, with no ".." segment.
	 *
	 * @param string $url Package URL.
	 * @return bool True when allowed.
	 */
	private function is_allowed_package_url( string $url ): bool {
		$parts = wp_parse_url( $url );
		if ( ! is_array( $parts ) ) {
			return false;
		}

		$scheme = strtolower( (string) ( $parts['scheme'] ?? '' ) );
		$host   = strtolower( (string) ( $parts['host'] ?? '' ) );
		$path   = (string) ( $parts['path'] ?? '' );

		// str_starts_with()/str_ends_with() below are plain string prefix/suffix
		// checks, not path normalisation -- a path containing a ".." segment
		// could still textually satisfy both while an HTTP client resolves it
		// (before the request is even sent) to a different location on this
		// same trusted host, e.g. escaping UPDATE_PATH into another product's
		// /wp-updates/<slug>/ folder. Reject any ".." segment outright rather
		// than relying on prefix/suffix matching alone.
		if ( str_contains( $path, '..' ) ) {
			return false;
		}

		return 'https' === $scheme
			&& self::UPDATE_HOST === $host
			&& str_starts_with( $path, self::UPDATE_PATH )
			&& str_ends_with( $path, '.zip' );
	}

	/**
	 * Checks that a string is a 64-character hexadecimal SHA-256 digest.
	 *
	 * @param string $hash Digest to check.
	 * @return bool True when valid.
	 */
	private function is_valid_sha256( string $hash ): bool {
		return preg_match( '/^[a-f0-9]{64}$/i', $hash ) === 1;
	}

	/**
	 * Checks whether an upgrade concerns this plugin.
	 *
	 * @param array $hook_extra Details of the upgrade.
	 * @return bool True when this plugin is being updated.
	 */
	private function is_plugin_update( array $hook_extra ): bool {
		if ( isset( $hook_extra['plugin'] ) && WP_SAM_PLUGIN_BASENAME === $hook_extra['plugin'] ) {
			return true;
		}

		return isset( $hook_extra['plugins'] )
			&& is_array( $hook_extra['plugins'] )
			&& in_array( WP_SAM_PLUGIN_BASENAME, $hook_extra['plugins'], true );
	}
}
