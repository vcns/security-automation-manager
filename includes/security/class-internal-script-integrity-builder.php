<?php
/**
 * Adds Subresource Integrity to first-party (theme/plugin/core) <script src>
 * and <link rel="stylesheet" href> tags -- the counterpart to
 * Dependency_Governance_Builder, which governs third-party origins only.
 *
 * Fundamentally different trust model from anything third-party: the hash is
 * computed by reading the exact local file this WordPress install is about
 * to serve, not by fetching a remote URL and trusting whatever comes back.
 * There is no "compromised CDN" risk here -- if an attacker already has
 * write access to this server's filesystem, computing a hash from a local
 * read doesn't protect against that (nothing could); what it protects
 * against is the file being altered *after* the origin serves it -- a
 * tampering or caching-layer issue between this server and the browser,
 * the same threat SRI addresses for third-party assets, just without ever
 * trusting a third party to compute the hash.
 *
 * Hooks the same script_loader_tag / style_loader_tag filters
 * Nonce_Manager already uses to add its nonce attribute; both filters are
 * additive (each checks for its own attribute before adding it), so they
 * compose safely on the same tag.
 *
 * Per-surface opt-in, matching every other pillar's "nothing happens until
 * you deliberately turn it on" default -- unlike nonce injection, which is
 * core CSP plumbing this plugin always performs unconditionally (strict-
 * dynamic surfaces have no other way to trust a script at all), integrity
 * hashing here is purely additive hardening with no downside if left off,
 * so it gets the same opt-in treatment as the rest of the plugin's optional
 * pillars rather than being wired in unconditionally like the nonce.
 */

declare( strict_types=1 );

namespace WP_SAM\Security;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class Internal_Script_Integrity_Builder extends Request_Surface {

	public const PILLAR_KEY = 'internal-script-integrity';

	public const RESOURCE_SCRIPT = 'script';
	public const RESOURCE_STYLE  = 'style';

	// ── Bootstrap ─────────────────────────────────────────────────────────────

	public function register(): void {
		add_filter( 'script_loader_tag', array( $this, 'add_script_integrity' ), 20, 3 );
		add_filter( 'style_loader_tag', array( $this, 'add_style_integrity' ), 20, 4 );
	}

	// ── Filter callbacks ──────────────────────────────────────────────────────

	public function add_script_integrity( string $tag, string $handle, string $src ): string {
		return $this->maybe_add_integrity( $tag, self::RESOURCE_SCRIPT, $handle, $src, '<script ' );
	}

	public function add_style_integrity( string $tag, string $handle, string $href, string $media ): string {
		unset( $media );
		return $this->maybe_add_integrity( $tag, self::RESOURCE_STYLE, $handle, $href, '<link ' );
	}

	private function maybe_add_integrity( string $tag, string $resource_type, string $handle, string $url, string $needle ): string {
		if ( str_contains( $tag, 'integrity=' ) ) {
			return $tag;
		}

		$surface = $this->detect_surface();
		if ( ! $this->is_active( $surface ) ) {
			return $tag;
		}

		$path = self::resolve_local_path( $url );
		if ( null === $path ) {
			return $tag;
		}

		$hash = $this->get_or_compute_hash( $resource_type, $path, $url, $surface, $handle );
		if ( null === $hash ) {
			return $tag;
		}

		$attrs = 'integrity="' . esc_attr( $hash ) . '" crossorigin="anonymous" ';
		return str_replace( $needle, $needle . $attrs, $tag );
	}

	// ── Profile lookup ────────────────────────────────────────────────────────

	private function is_active( string $surface ): bool {
		global $wpdb;
		$table = $wpdb->prefix . 'sam_pillar_profiles';
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery,WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		$enabled = $wpdb->get_var( $wpdb->prepare( "SELECT enabled FROM {$table} WHERE pillar = %s AND surface = %s", self::PILLAR_KEY, $surface ) );
		return ! empty( $enabled );
	}

	// ── Local path resolution ────────────────────────────────────────────────

	/**
	 * Resolves an enqueued script/style URL to an absolute local filesystem
	 * path, or null if it isn't a first-party URL this plugin can safely
	 * read directly (a third-party origin, or a URL that doesn't map onto
	 * any of this install's known local directories).
	 *
	 * @return string|null Absolute, containment-checked realpath, or null.
	 */
	public static function resolve_local_path( string $url ): ?string {
		$origin = Dependency_Governance_Builder::normalize_origin( $url );
		if ( null === $origin || ! Dependency_Governance_Builder::is_first_party( $origin ) ) {
			return null;
		}

		$parts = wp_parse_url( str_starts_with( $url, '//' ) ? 'https:' . $url : $url );
		$path  = is_array( $parts ) ? (string) ( $parts['path'] ?? '' ) : '';
		if ( '' === $path ) {
			return null;
		}

		// Longest-prefix match against every known URL base this install
		// could have served the file from -- content (plugins/themes/
		// uploads/mu-plugins), wp-includes, wp-admin, and finally the site
		// root itself as a fallback.
		$bases = array(
			array( self::url_path( content_url() ), WP_CONTENT_DIR ),
			array( self::url_path( includes_url() ), ABSPATH . WPINC ),
			array( self::url_path( admin_url() ), ABSPATH . 'wp-admin' ),
			array( self::url_path( site_url() ), rtrim( ABSPATH, '/\\' ) ),
		);

		$candidate = null;
		foreach ( $bases as list( $base_path, $base_dir ) ) {
			if ( '' === $base_path ) {
				continue;
			}
			if ( 0 === strpos( $path, $base_path ) ) {
				$candidate = rtrim( $base_dir, '/\\' ) . substr( $path, strlen( $base_path ) );
				break;
			}
		}

		if ( null === $candidate ) {
			return null;
		}

		$real     = realpath( $candidate );
		$abs_real = realpath( ABSPATH );
		if ( false === $real || false === $abs_real || 0 !== strpos( $real, $abs_real ) ) {
			return null;
		}

		return $real;
	}

	private static function url_path( string $url ): string {
		$parts = wp_parse_url( $url );
		return is_array( $parts ) ? rtrim( (string) ( $parts['path'] ?? '' ), '/' ) : '';
	}

	// ── Hashing + inventory ──────────────────────────────────────────────────

	/**
	 * Returns 'sha384-<base64>' for $path, reusing the last computed hash
	 * when the file's size and mtime haven't changed since -- so an
	 * unchanged file is never re-read on every request, only when it
	 * actually changes (a plugin/theme update, a manual edit, anything).
	 */
	private function get_or_compute_hash( string $resource_type, string $path, string $url, string $surface, string $handle ): ?string {
		$mtime = @filemtime( $path );
		$size  = @filesize( $path );
		if ( false === $mtime || false === $size ) {
			return null;
		}

		global $wpdb;
		$table = $wpdb->prefix . 'sam_internal_asset_inventory';
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery,WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		$row = $wpdb->get_row( $wpdb->prepare( "SELECT * FROM {$table} WHERE resource_type = %s AND path = %s", $resource_type, $path ), ARRAY_A );

		$now = current_time( 'mysql', true );

		if ( is_array( $row ) && (int) $row['file_mtime'] === $mtime && (int) $row['file_size'] === $size ) {
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
			$wpdb->update(
				$table,
				array(
					'url'          => $url,
					'surface'      => $surface,
					'handle'       => $handle,
					'last_seen_at' => $now,
					'updated_at'   => $now,
				),
				array( 'id' => (int) $row['id'] ),
				array( '%s', '%s', '%s', '%s', '%s' ),
				array( '%d' )
			);
			return (string) $row['hash'];
		}

		$content = @file_get_contents( $path );
		if ( false === $content ) {
			return null;
		}
		$hash = 'sha384-' . base64_encode( hash( 'sha384', $content, true ) );

		$data = array(
			'resource_type' => $resource_type,
			'path'          => $path,
			'url'           => $url,
			'surface'       => $surface,
			'handle'        => $handle,
			'hash'          => $hash,
			'file_size'     => $size,
			'file_mtime'    => $mtime,
			'last_seen_at'  => $now,
			'updated_at'    => $now,
		);

		if ( is_array( $row ) ) {
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
			$wpdb->update( $table, $data, array( 'id' => (int) $row['id'] ), array( '%s', '%s', '%s', '%s', '%s', '%s', '%d', '%d', '%s', '%s' ), array( '%d' ) );
		} else {
			$data['first_seen_at'] = $now;
			$data['created_at']    = $now;
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery
			$wpdb->insert( $table, $data, array( '%s', '%s', '%s', '%s', '%s', '%s', '%d', '%d', '%s', '%s', '%s', '%s' ) );
		}

		return $hash;
	}
}
