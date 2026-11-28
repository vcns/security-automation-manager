<?php
/**
 * Turns off WordPress's in-browser media processing while the admin CSP is
 * enforced.
 *
 * Since WordPress 7.1, the block editor and Media → Add New Media File
 * resize and convert images in the browser before uploading them. That
 * pipeline runs in a blob: worker, fetches blob: URLs, compiles
 * WebAssembly and evaluates generated code, so it needs `worker-src blob:`,
 * `connect-src blob:`, `'wasm-unsafe-eval'` and `'unsafe-eval'` -- found by
 * testing WordPress 7.2 RC3 under every combination of those. SAM never
 * allows `'unsafe-eval'` and has no `connect-src blob:` toggle, so under an
 * enforced admin policy the processing step is blocked, and WordPress has
 * no fallback: the upload fails ("Failed to process ... may be corrupted").
 *
 * Returning false from core's own `wp_client_side_media_processing_enabled`
 * filter (since 7.1) sends uploads to the server, which processes them the
 * way every earlier WordPress version does. Nothing in the policy is
 * loosened. The check is deliberately not tied to the current request's
 * surface: core also reads this filter while serving the REST media
 * endpoints, and both sides must agree on where processing happens.
 *
 * Report-only and disabled admin surfaces are left alone: nothing is
 * blocked there, so in-browser processing works. On WordPress earlier than
 * 7.1 the filter is never applied, so this does nothing.
 *
 * A site that has made in-browser processing work some other way can turn
 * it back on with a later-priority filter on the same hook.
 */

declare( strict_types=1 );

namespace WP_SAM\CSP;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Client_Side_Media_Guard {

	public const FILTER = 'wp_client_side_media_processing_enabled';

	private Policy_Data_Loader $data_loader;

	private ?bool $admin_enforced = null;

	public function __construct( ?Policy_Data_Loader $data_loader = null ) {
		$this->data_loader = $data_loader ?? new Wpdb_Policy_Data_Loader();
	}

	public function register(): void {
		add_filter( self::FILTER, array( $this, 'filter_enabled' ) );
	}

	/**
	 * @param mixed $enabled Core's value: true in a secure context.
	 * @return bool False while the admin surface is enforced.
	 */
	public function filter_enabled( mixed $enabled ): bool {
		if ( ! $enabled ) {
			return false;
		}

		return ! $this->admin_enforced();
	}

	/**
	 * Whether the admin surface's CSP mode is enforce. Read once per request:
	 * core can apply the filter several times while building one page.
	 */
	public function admin_enforced(): bool {
		if ( null === $this->admin_enforced ) {
			$profile              = $this->data_loader->load_profile( 'admin' );
			$this->admin_enforced = is_array( $profile ) && 'enforce' === (string) ( $profile['mode'] ?? '' );
		}

		return $this->admin_enforced;
	}
}
