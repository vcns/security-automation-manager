<?php
/**
 * Passively inventories third-party <script src> and <link rel="stylesheet">
 * origins from real page loads, lets an administrator classify each origin,
 * and -- only once a surface is explicitly switched to enforce mode --
 * removes elements from origins the administrator has explicitly blocked or
 * whose declared Subresource Integrity hash no longer matches.
 *
 * Deliberately diverges from a naive "default-deny everything not on an
 * allowlist" design: a freshly discovered origin is stored as
 * 'unclassified', never 'prohibited'. Report mode (the default for every
 * surface) never removes anything, matching this plugin's report-first
 * philosophy everywhere else (CSP's own report-only default, the simple
 * pillars' "nothing happens until you deliberately turn it on"). Enforce
 * mode, once an administrator opts a surface into it, still only ever
 * removes an origin the administrator explicitly classified 'prohibited',
 * or an 'immutable_pinned' origin whose admin-declared expected_sri no
 * longer matches what the page actually served -- an unclassified origin is
 * never silently blocked, even in enforce mode.
 *
 * SRI is never fabricated: expected_sri only ever comes from an
 * administrator typing/pasting a hash they already trust (e.g. from a
 * locally downloaded copy of the vetted file, or the vendor's published
 * hash) into the admin UI. This class only ever *compares* against that
 * value -- it never computes a hash from a live remote fetch, which would
 * defeat the entire point of SRI if the remote origin were compromised.
 */

declare( strict_types=1 );

namespace WP_SAM\Security;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class Dependency_Governance_Builder extends Content_Rewriter {

	public const PILLAR_KEY = 'dependency-governance';

	public const RESOURCE_SCRIPT = 'script';
	public const RESOURCE_STYLE  = 'style';

	public const CLASSIFICATIONS = array(
		'unclassified',
		'first_party',
		'immutable_pinned',
		'mutable_provider',
		'exception',
		'prohibited',
	);

	private const MARKER = 'data-wp-sam-dependency-remove';

	protected function is_active( string $surface ): bool {
		return null !== $this->load_profile( $surface );
	}

	private function load_profile( string $surface ): ?array {
		global $wpdb;
		$table = $wpdb->prefix . 'sam_pillar_profiles';
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery,WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		$row = $wpdb->get_row( $wpdb->prepare( "SELECT * FROM {$table} WHERE pillar = %s AND surface = %s LIMIT 1", self::PILLAR_KEY, $surface ), ARRAY_A );
		if ( empty( $row ) || empty( $row['enabled'] ) ) {
			return null;
		}
		return $row;
	}

	public static function extract_mode( array $profile ): string {
		$payload = json_decode( (string) ( $profile['payload'] ?? '' ), true );
		$mode    = is_array( $payload ) ? (string) ( $payload['mode'] ?? '' ) : '';
		return 'enforce' === $mode ? 'enforce' : 'report';
	}

	// ── Origin classification ────────────────────────────────────────────────

	/**
	 * Normalises a script/link URL to its origin (scheme + host, lower-case,
	 * no path or query, no default-port suffix), or null when the URL is
	 * relative/root-relative (first-party by definition -- resolves against
	 * this site) or unparseable.
	 */
	public static function normalize_origin( string $url ): ?string {
		$url = trim( $url );
		if ( '' === $url ) {
			return null;
		}

		// Reject any explicit non-HTTP scheme (data:, javascript:, blob:, …).
		if ( preg_match( '/^([a-z][a-z0-9+.\-]*):/i', $url, $matches )
			&& ! in_array( strtolower( $matches[1] ), array( 'http', 'https' ), true ) ) {
			return null;
		}

		$parseable = str_starts_with( $url, '//' ) ? 'https:' . $url : $url;
		$parts     = wp_parse_url( $parseable );

		if ( ! is_array( $parts ) || empty( $parts['host'] ) ) {
			// No host: relative/root-relative, resolves against this site.
			return 'first-party';
		}

		$scheme = strtolower( (string) ( $parts['scheme'] ?? 'https' ) );
		$host   = strtolower( (string) $parts['host'] );

		return $scheme . '://' . $host;
	}

	/**
	 * @return string[] Normalised hosts of this site (home_url + site_url).
	 */
	private static function first_party_origins(): array {
		$origins = array();
		foreach ( array( 'home_url', 'site_url' ) as $source ) {
			$parts = wp_parse_url( (string) call_user_func( $source ) );
			if ( is_array( $parts ) && ! empty( $parts['host'] ) ) {
				$scheme    = strtolower( (string) ( $parts['scheme'] ?? 'https' ) );
				$origins[] = $scheme . '://' . strtolower( (string) $parts['host'] );
			}
		}
		return array_values( array_unique( $origins ) );
	}

	public static function is_first_party( string $origin ): bool {
		return 'first-party' === $origin || in_array( $origin, self::first_party_origins(), true );
	}

	/**
	 * Extracts (resource_type, url) for the tag the processor is currently
	 * positioned at, or null if it isn't a resource this pillar governs (an
	 * unrecognised tag/rel, or a missing/empty src|href). Shared by the
	 * per-request rewrite pass and Dependency_Integrity_Monitor's proactive
	 * scan so both recognise exactly the same set of elements.
	 *
	 * @return array{0:string,1:string}|null
	 */
	public static function extract_governed_resource( \WP_HTML_Tag_Processor $processor ): ?array {
		$tag = $processor->get_tag();

		if ( 'SCRIPT' === $tag ) {
			$src = $processor->get_attribute( 'src' );
			return ( is_string( $src ) && '' !== trim( $src ) ) ? array( self::RESOURCE_SCRIPT, $src ) : null;
		}

		if ( 'LINK' === $tag ) {
			$rel = $processor->get_attribute( 'rel' );
			if ( ! is_string( $rel ) || 'stylesheet' !== strtolower( trim( $rel ) ) ) {
				return null;
			}
			$href = $processor->get_attribute( 'href' );
			return ( is_string( $href ) && '' !== trim( $href ) ) ? array( self::RESOURCE_STYLE, $href ) : null;
		}

		return null;
	}

	// ── Rewrite pass ──────────────────────────────────────────────────────────

	protected function rewrite( string $html, string $surface ): string {
		if ( false === stripos( $html, '<script' ) && false === stripos( $html, '<link' ) ) {
			return $html;
		}

		if ( ! class_exists( 'WP_HTML_Tag_Processor' ) ) {
			return $html;
		}

		$profile = $this->load_profile( $surface );
		if ( null === $profile ) {
			return $html;
		}
		$mode = self::extract_mode( $profile );

		$inventory = $this->load_inventory( $surface );
		$seen      = array();
		$to_remove = 0;

		try {
			$processor = new \WP_HTML_Tag_Processor( $html );

			while ( $processor->next_tag() ) {
				$resource = self::extract_governed_resource( $processor );
				if ( null === $resource ) {
					continue;
				}
				list( $resource_type, $url ) = $resource;
				$this->classify_and_maybe_mark( $processor, $resource_type, $url, $surface, $mode, $inventory, $seen, $to_remove );
			}

			$this->persist_inventory( $inventory );

			if ( 0 === $to_remove ) {
				return $html;
			}

			$working = $processor->get_updated_html();
			return is_string( $working ) && '' !== $working ? $this->strip_marked_elements( $working ) : $html;
		} catch ( \Throwable $unused ) {
			return $html;
		}
	}

	/**
	 * Classifies one element's origin, records/updates its inventory row,
	 * and -- in enforce mode -- marks it for removal when the administrator
	 * has explicitly classified it 'prohibited', or when it's
	 * 'immutable_pinned' with an SRI hash that no longer matches.
	 *
	 * @param array<string,array> $inventory Loaded rows, keyed by "type:origin"; mutated in place.
	 * @param array<string,true>  $seen      Origins already touched this pass (dedup evidence bumps).
	 */
	private function classify_and_maybe_mark(
		\WP_HTML_Tag_Processor $processor,
		string $resource_type,
		string $url,
		string $surface,
		string $mode,
		array &$inventory,
		array &$seen,
		int &$to_remove
	): void {
		$origin = self::normalize_origin( $url );
		if ( null === $origin || self::is_first_party( $origin ) ) {
			return;
		}

		$key = $resource_type . ':' . $origin;

		if ( ! isset( $inventory[ $key ] ) ) {
			$inventory[ $key ] = array(
				'surface'        => $surface,
				'resource_type'  => $resource_type,
				'origin'         => $origin,
				'classification' => 'unclassified',
				'expected_sri'   => null,
				'evidence_count' => 0,
				'is_new'         => true,
				'touched'        => false,
			);
		}

		if ( ! isset( $seen[ $key ] ) ) {
			++$inventory[ $key ]['evidence_count'];
			$inventory[ $key ]['touched'] = true;
			$seen[ $key ]                 = true;
		}

		if ( 'enforce' !== $mode ) {
			return;
		}

		$classification = $inventory[ $key ]['classification'];

		if ( 'prohibited' === $classification ) {
			$processor->set_attribute( self::MARKER, true );
			++$to_remove;
			return;
		}

		if ( 'immutable_pinned' === $classification && ! empty( $inventory[ $key ]['expected_sri'] ) ) {
			$integrity = $processor->get_attribute( 'integrity' );
			if ( ! is_string( $integrity ) || trim( $integrity ) !== trim( (string) $inventory[ $key ]['expected_sri'] ) ) {
				$processor->set_attribute( self::MARKER, true );
				++$to_remove;
			}
		}
	}

	/**
	 * Removes every <script>...</script> or void <link ...> element carrying
	 * the removal marker. Quote-aware span matching, same technique as the
	 * rest of this plugin's HTML rewrites; any surviving marker (an element
	 * that couldn't be resolved, e.g. unclosed at EOF) means the original,
	 * unmarked HTML is returned instead -- never a partially-rewritten page.
	 */
	private function strip_marked_elements( string $html ): string {
		$marker = self::MARKER;
		$attrs  = '(?:[^"\'>]++|"[^"]*+"|\'[^\']*+\')*+';

		$working = preg_replace(
			'#<link(?=[\s/>])' . $attrs . ' ' . $marker . $attrs . '/?>#i',
			'',
			$html
		);
		if ( ! is_string( $working ) ) {
			return $html;
		}

		$working = preg_replace_callback(
			'#<script(?=[\s/>])' . $attrs . '>.*?</script\b[^>]*>#is',
			static function ( array $m ) use ( $marker ): string {
				return str_contains( $m[0], ' ' . $marker ) ? '' : $m[0];
			},
			$working
		);
		if ( ! is_string( $working ) ) {
			return $html;
		}

		return false !== strpos( $working, $marker ) ? $html : $working;
	}

	// ── Inventory persistence ────────────────────────────────────────────────

	/**
	 * @return array<string,array> Existing rows for this surface, keyed by "type:origin".
	 */
	private function load_inventory( string $surface ): array {
		global $wpdb;
		$table = $wpdb->prefix . 'sam_dependency_inventory';
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery,WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		$rows = $wpdb->get_results( $wpdb->prepare( "SELECT * FROM {$table} WHERE surface = %s", $surface ), ARRAY_A );

		$by_key = array();
		foreach ( ! empty( $rows ) ? $rows : array() as $row ) {
			$key            = $row['resource_type'] . ':' . $row['origin'];
			$row['is_new']  = false;
			$row['touched'] = false;
			$by_key[ $key ] = $row;
		}
		return $by_key;
	}

	private function persist_inventory( array $inventory ): void {
		global $wpdb;
		$table = $wpdb->prefix . 'sam_dependency_inventory';
		$now   = current_time( 'mysql', true );

		foreach ( $inventory as $row ) {
			if ( empty( $row['touched'] ) ) {
				continue;
			}

			if ( ! empty( $row['is_new'] ) ) {
				// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery
				$wpdb->insert(
					$table,
					array(
						'surface'        => $row['surface'],
						'resource_type'  => $row['resource_type'],
						'origin'         => $row['origin'],
						'classification' => 'unclassified',
						'evidence_count' => 1,
						'first_seen_at'  => $now,
						'last_seen_at'   => $now,
						'created_at'     => $now,
						'updated_at'     => $now,
					),
					array( '%s', '%s', '%s', '%s', '%d', '%s', '%s', '%s', '%s' )
				);
				continue;
			}

			// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
			$wpdb->update(
				$table,
				array(
					'evidence_count' => (int) $row['evidence_count'],
					'last_seen_at'   => $now,
					'updated_at'     => $now,
				),
				array( 'id' => (int) $row['id'] ),
				array( '%d', '%s', '%s' ),
				array( '%d' )
			);
		}
	}
}
