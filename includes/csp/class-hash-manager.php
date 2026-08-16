<?php
/**
 * Computes and manages SHA-256 hashes for inline script and style blocks.
 *
 * Implements §4.5 of the directive:
 *   - Hooks into wp_head / wp_footer / admin_head / admin_footer output
 *     buffering to capture inline script and style blocks at render time.
 *   - Computes sha256 hash, base64-encodes it, stores in csp_hash_inventory.
 *   - Retires hashes whose content has changed (fingerprint mismatch).
 *   - Passes the current-request hash map back to Scheduler so retire_stale()
 *     receives real data rather than an empty array.
 *
 * Note: hash-based inline approval is an alternative to nonces when
 * the inline content is truly static. For dynamic inline blocks, nonces remain
 * the preferred path.
 */

declare( strict_types=1 );

namespace WP_SAM\CSP;

use WP_SAM\Modules\Audit_Log;
use WP_SAM\Modules\Feature_Gate;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class Hash_Manager {

	private Audit_Log $audit;
	private Feature_Gate $gate;

	/**
	 * Hashes captured during the current request, keyed by hash_value => fingerprint.
	 * Used to feed a real map into retire_stale() rather than an empty array.
	 *
	 * @var array<string,string>
	 */
	private array $captured_hashes = array();

	public function __construct( Audit_Log $audit, Feature_Gate $gate ) {
		$this->audit = $audit;
		$this->gate  = $gate;
	}

	// ── Bootstrap ─────────────────────────────────────────────────────────────

	/**
	 * Registers output-buffering hooks to capture inline blocks at render time.
	 * Called from Plugin::bootstrap().
	 */
	public function register(): void {
		// Front-end surfaces.
		add_action( 'wp_head', array( $this, 'start_buffer' ) );
		add_action( 'wp_footer', array( $this, 'end_buffer_frontend' ), PHP_INT_MAX );

		// Admin surface.
		add_action( 'admin_head', array( $this, 'start_buffer' ) );
		add_action( 'admin_footer', array( $this, 'end_buffer_admin' ), PHP_INT_MAX );

		// Login surface (wp-login.php emits login_head / login_footer).
		add_action( 'login_head', array( $this, 'start_buffer' ) );
		add_action( 'login_footer', array( $this, 'end_buffer_login' ), PHP_INT_MAX );
	}

	// ── Output buffer callbacks ───────────────────────────────────────────────

	/**
	 * Starts an output buffer. Called at the top of each surface head hook.
	 * Multiple nested ob_start() calls are safe; PHP maintains a buffer stack.
	 */
	public function start_buffer(): void {
		ob_start();
	}

	public function end_buffer_frontend(): void {
		$this->flush_buffer( 'frontend' );
	}

	public function end_buffer_admin(): void {
		$this->flush_buffer( 'admin' );
	}

	public function end_buffer_login(): void {
		$this->flush_buffer( 'login' );
	}

	/**
	 * Flushes the current output buffer, parses it for inline blocks,
	 * records hashes, then re-emits the content unchanged.
	 *
	 * @param string $surface  'frontend' | 'admin' | 'login'
	 */
	private function flush_buffer( string $surface ): void {
		if ( 0 === ob_get_level() ) {
			return;
		}

		$html = ob_get_clean();

		if ( false === $html || '' === $html ) {
			return;
		}

		$this->process_inline_blocks( $html, $surface );

		// Re-emit content so the page renders normally.
		echo $html; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
	}

	// ── Inline block processing ───────────────────────────────────────────────

	/**
	 * Extracts inline <script> and <style> blocks from HTML, computes hashes,
	 * and stores them in the inventory.
	 *
	 * @param string $html     Raw HTML output captured from the buffer.
	 * @param string $surface  CSP surface identifier.
	 */
	private function process_inline_blocks( string $html, string $surface ): void {
		$this->extract_and_record( $html, 'script', 'script-src', $surface );
		$this->extract_and_record( $html, 'style', 'style-src', $surface );
		$this->extract_and_record_style_attributes( $html, $surface );
	}

	/**
	 * Extracts inline style="" attribute values from arbitrary tags and records
	 * their hashes under style-src-attr.
	 *
	 * Unlike <style> element blocks, a hash source only takes effect in an
	 * attribute context (style attributes, event handlers, javascript: URLs)
	 * when the 'unsafe-hashes' keyword is also present in the directive --
	 * CSP3 §6.1.2. Policy_Builder adds 'unsafe-hashes' to style-src-attr
	 * automatically whenever at least one hash is present for it.
	 *
	 * Regex-based extraction over raw HTML (matching this class's existing
	 * approach for <script>/<style> elements), not a real DOM parse -- a
	 * literal "style=" substring inside unrelated script/text content could
	 * in principle produce a spurious, never-matched hash entry. That's
	 * cosmetic noise, not a security concern: an unused hash only ever
	 * narrows what it exactly matches, it never broadens the policy.
	 *
	 * @param string $html    Raw HTML.
	 * @param string $surface CSP surface identifier.
	 */
	private function extract_and_record_style_attributes( string $html, string $surface ): void {
		if ( ! preg_match_all( '/\sstyle\s*=\s*(["\'])(.*?)\1/is', $html, $matches, PREG_SET_ORDER ) ) {
			return;
		}

		foreach ( $matches as $match ) {
			$content = trim( $match[2] );
			if ( '' === $content ) {
				continue;
			}

			// Browsers hash the parsed (HTML-entity-decoded) attribute value, not
			// the raw source bytes -- decode here so the stored hash matches what
			// the browser actually computes.
			$decoded   = html_entity_decode( $content, ENT_QUOTES | ENT_HTML5 );
			$canonical = str_replace( array( "\r\n", "\r" ), "\n", $decoded );

			$this->record_hash( $canonical, 'style-src-attr', $surface );
		}
	}

	/**
	 * Extracts all inline blocks for a given tag type and records their hashes.
	 *
	 * @param string $html      Raw HTML.
	 * @param string $tag       'script' or 'style'.
	 * @param string $directive CSP directive the hash applies to.
	 * @param string $surface   CSP surface identifier.
	 */
	private function extract_and_record(
		string $html,
		string $tag,
		string $directive,
		string $surface
	): void {
		// Match inline blocks only (no src= or href= attribute on the opening tag).
		// Uses a non-greedy match and the s (DOTALL) flag to handle multi-line content.
		$pattern = sprintf(
			'/<(?:%s)(?:\s+(?!src=)[^>]*)?>(.+?)<\/%s>/is',
			preg_quote( $tag, '/' ),
			preg_quote( $tag, '/' )
		);

		if ( ! preg_match_all( $pattern, $html, $matches, PREG_SET_ORDER ) ) {
			return;
		}

		foreach ( $matches as $match ) {
			$content = $match[1];

			// Skip empty or whitespace-only blocks.
			if ( '' === trim( $content ) ) {
				continue;
			}

			// Skip nonce-carrying script tags -- these are already covered by the
			// nonce manager and do not need a hash entry.
			if ( 'script' === $tag && str_contains( $match[0], 'nonce=' ) ) {
				continue;
			}

			// Canonicalise: normalise line endings only. Do not strip whitespace
			// aggressively as that changes the hash value vs the browser's calculation.
			$canonical = str_replace( "\r\n", "\n", $content );
			$canonical = str_replace( "\r", "\n", $canonical );

			$this->record_hash( $canonical, $directive, $surface );
		}
	}

	// ── Public API ────────────────────────────────────────────────────────────

	/**
	 * Computes an inline hash and stores it in the DB inventory.
	 *
	 * @param string $content     Raw inline script/style content, or a style
	 *                            attribute's value for 'style-src-attr'.
	 * @param string $directive   'script-src', 'style-src', or 'style-src-attr'.
	 * @param string $surface     'frontend' | 'admin' | 'login' | 'api'.
	 * @param string $source_file Optional: file where the inline block originates.
	 * @return string             'sha256-{base64}' value for direct use in CSP header.
	 */
	public function record_hash(
		string $content,
		string $directive,
		string $surface,
		string $source_file = ''
	): string {
		$hash_raw    = hash( 'sha256', $content, true );
		$hash_b64    = base64_encode( $hash_raw );
		$fingerprint = hash( 'sha256', $content );

		// Track in the per-request map so retire_stale() receives real data.
		$this->captured_hashes[ $hash_b64 ] = $fingerprint;

		$this->upsert( $hash_b64, $fingerprint, $directive, $surface, $source_file );

		return "sha256-{$hash_b64}";
	}

	/**
	 * Returns the hash map captured during the current request.
	 * Keys are base64-encoded hash values; values are content fingerprints.
	 *
	 * @return array<string,string>
	 */
	public function get_captured_hashes(): array {
		return $this->captured_hashes;
	}

	/**
	 * Runs a hash audit: retires any stored hashes for inline blocks that no
	 * longer exist or whose content fingerprint has changed.
	 *
	 * Called from Scheduler::run_daily_scan() and Scheduler::run_manual_scan().
	 *
	 * @param array<string,string> $current_hashes hash_value => fingerprint from current crawl/request.
	 * @param string               $surface
	 * @return int Number of hashes retired.
	 */
	public function retire_stale( array $current_hashes, string $surface ): int {
		global $wpdb;
		$table = $wpdb->prefix . 'csp_hash_inventory';
		$now   = current_time( 'mysql', true );

		$all = $wpdb->get_results(
			$wpdb->prepare(
				// phpcs:ignore WordPress.DB.DirectDatabaseQuery,WordPress.DB.PreparedSQL.InterpolatedNotPrepared
				"SELECT id, hash_value, content_fingerprint FROM {$table} WHERE surface = %s AND status = 'active'",
				$surface
			),
			ARRAY_A
		);
		$all = ! empty( $all ) ? $all : array();

		// If current_hashes is empty, the caller had no capture data.
		// Skip retirement rather than retiring everything blindly.
		if ( empty( $current_hashes ) ) {
			return 0;
		}

		$retired = 0;
		foreach ( $all as $row ) {
			$hv = $row['hash_value'];
			if ( ! isset( $current_hashes[ $hv ] ) || $current_hashes[ $hv ] !== $row['content_fingerprint'] ) {
				$wpdb->update(
					$table,
					array(
						'status'     => 'retired',
						'retired_at' => $now,
					),
					array( 'id' => (int) $row['id'] ),
					array( '%s', '%s' ),
					array( '%d' )
				);
				++$retired;
			}
		}

		return $retired;
	}

	/**
	 * Returns all active hashes for a surface as 'sha256-{b64}' strings.
	 */
	public function get_active_hashes( string $surface, string $directive ): array {
		global $wpdb;
		$table = $wpdb->prefix . 'csp_hash_inventory';
		$rows  = $wpdb->get_results(
			$wpdb->prepare(
				// phpcs:ignore WordPress.DB.DirectDatabaseQuery,WordPress.DB.PreparedSQL.InterpolatedNotPrepared
				"SELECT hash_algo, hash_value FROM {$table} WHERE surface = %s AND directive = %s AND status = 'active'",
				$surface,
				$directive
			),
			ARRAY_A
		);
		$rows = ! empty( $rows ) ? $rows : array();

		return array_map(
			static function ( $r ) {
				return "{$r['hash_algo']}-{$r['hash_value']}";
			},
			$rows
		);
	}

	// ── Internal ──────────────────────────────────────────────────────────────

	private function upsert(
		string $hash_b64,
		string $fingerprint,
		string $directive,
		string $surface,
		string $source_file
	): void {
		global $wpdb;
		$table = $wpdb->prefix . 'csp_hash_inventory';
		$now   = current_time( 'mysql', true );

		$existing = $wpdb->get_var(
			$wpdb->prepare(
				// phpcs:ignore WordPress.DB.DirectDatabaseQuery,WordPress.DB.PreparedSQL.InterpolatedNotPrepared
				"SELECT id FROM {$table} WHERE directive = %s AND hash_value = %s LIMIT 1",
				$directive,
				$hash_b64
			)
		);

		if ( $existing ) {
			$wpdb->update(
				$table,
				array(
					'last_seen_at' => $now,
					'status'       => 'active',
				),
				array( 'id' => (int) $existing ),
				array( '%s', '%s' ),
				array( '%d' )
			);
		} else {
			$wpdb->insert(
				$table,
				array(
					'surface'             => $surface,
					'directive'           => $directive,
					'hash_algo'           => 'sha256',
					'hash_value'          => $hash_b64,
					'content_fingerprint' => $fingerprint,
					'source_file'         => sanitize_text_field( $source_file ),
					'status'              => 'active',
					'first_seen_at'       => $now,
					'last_seen_at'        => $now,
				),
				array( '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s' )
			);
		}
	}
}
