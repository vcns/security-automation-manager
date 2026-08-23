<?php
/**
 * Reusable GET-param sorting, filtering, and pagination helpers for admin tables.
 */

declare( strict_types=1 );

namespace WP_SAM\Admin;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Table_Query {

	// ── GET-param readers ───────────────────────────────────────────────────────

	/**
	 * Reads a multi-select GET param (e.g. `?col[]=a&col[]=b`) as a sanitized,
	 * deduplicated list of non-empty strings.
	 */
	public static function multi_param( string $key ): array {
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- read-only table filter, not a state-changing action.
		$raw = isset( $_GET[ $key ] ) ? wp_unslash( $_GET[ $key ] ) : array();
		if ( ! is_array( $raw ) ) {
			return array();
		}

		$out = array();
		foreach ( $raw as $value ) {
			$value = sanitize_text_field( (string) $value );
			if ( '' !== $value ) {
				$out[] = $value;
			}
		}

		return array_values( array_unique( $out ) );
	}

	/** Reads a single free-text GET param, sanitized and trimmed. */
	public static function text_param( string $key ): string {
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- read-only table filter, not a state-changing action.
		return isset( $_GET[ $key ] ) ? trim( sanitize_text_field( wp_unslash( (string) $_GET[ $key ] ) ) ) : '';
	}

	/** Reads a single numeric GET param, or null when absent/blank. */
	public static function int_param( string $key ): ?int {
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- read-only table filter, not a state-changing action.
		if ( ! isset( $_GET[ $key ] ) || '' === $_GET[ $key ] ) {
			return null;
		}
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended
		return (int) wp_unslash( $_GET[ $key ] );
	}

	// ── Sorting ──────────────────────────────────────────────────────────────────

	/**
	 * Resolves a user-supplied sort key/direction against a whitelist.
	 *
	 * $whitelist shape: [ 'key' => [ 'expr' => '<literal SQL column or CASE expr>', 'default_dir' => 'asc'|'desc' ], ... ]
	 *
	 * The SQL expression is always the hardcoded PHP literal from $whitelist,
	 * never derived from user input -- $raw_sort only selects *which* whitelist
	 * entry to use. Unknown keys silently fall back to $default_key. This is the
	 * entire SQL-injection defense for ORDER BY, since $wpdb->prepare() cannot
	 * parameterize identifiers.
	 */
	public static function resolve_sort( array $whitelist, string $default_key, ?string $raw_sort, ?string $raw_dir ): array {
		$key = ( null !== $raw_sort && isset( $whitelist[ $raw_sort ] ) ) ? $raw_sort : $default_key;
		$col = $whitelist[ $key ];

		$dir = null !== $raw_dir ? strtoupper( $raw_dir ) : strtoupper( (string) $col['default_dir'] );
		if ( ! in_array( $dir, array( 'ASC', 'DESC' ), true ) ) {
			$dir = strtoupper( (string) $col['default_dir'] );
		}

		return array(
			'key'  => $key,
			'expr' => $col['expr'],
			'dir'  => $dir,
		);
	}

	/** Builds the literal `ORDER BY` clause from a resolved sort. */
	public static function order_by_sql( array $resolved ): string {
		return 'ORDER BY ' . $resolved['expr'] . ' ' . $resolved['dir'];
	}

	// ── Filter WHERE-fragment builders ──────────────────────────────────────────
	// All builders return null when the filter is inactive, or ['sql' => '...',
	// 'args' => [...]] with placeholders that must be passed through $wpdb->prepare().

	public static function multi_select_where( string $column, array $raw_values ): ?array {
		$values = array_slice( array_values( array_unique( $raw_values ) ), 0, 50 );
		if ( empty( $values ) ) {
			return null;
		}

		$placeholders = implode( ',', array_fill( 0, count( $values ), '%s' ) );

		return array(
			'sql'  => "{$column} IN ({$placeholders})",
			'args' => $values,
		);
	}

	public static function equals_where( string $column, string $raw_value ): ?array {
		$value = trim( $raw_value );
		if ( '' === $value ) {
			return null;
		}

		return array(
			'sql'  => "{$column} = %s",
			'args' => array( $value ),
		);
	}

	public static function like_where( \wpdb $wpdb, string $column, string $raw_term ): ?array {
		$term = trim( $raw_term );
		if ( '' === $term ) {
			return null;
		}

		return array(
			'sql'  => "{$column} LIKE %s",
			'args' => array( '%' . $wpdb->esc_like( $term ) . '%' ),
		);
	}

	/**
	 * Same as like_where(), but matches if the term is found in ANY of the
	 * given columns (e.g. a "Blocked URI" search field that should match
	 * against either the grouped blocked_host column or the full blocked_uri
	 * column, since a filter box only has one place to type into).
	 */
	public static function like_where_any( \wpdb $wpdb, array $columns, string $raw_term ): ?array {
		$term = trim( $raw_term );
		if ( '' === $term || empty( $columns ) ) {
			return null;
		}

		$like    = '%' . $wpdb->esc_like( $term ) . '%';
		$clauses = array();
		$args    = array();
		foreach ( $columns as $column ) {
			$clauses[] = "{$column} LIKE %s";
			$args[]    = $like;
		}

		return array(
			'sql'  => '(' . implode( ' OR ', $clauses ) . ')',
			'args' => $args,
		);
	}

	public static function numeric_gte_where( string $column, ?int $raw_min ): ?array {
		if ( null === $raw_min ) {
			return null;
		}

		return array(
			'sql'  => "{$column} >= %d",
			'args' => array( $raw_min ),
		);
	}

	/**
	 * Validates Y-m-d or datetime-local (Y-m-dTH:i) inputs; returns a combined
	 * fragment for whichever bound(s) are present. A bare date defaults to the
	 * start/end of that day, matching the previous date-only behaviour; a
	 * datetime-local value is used at minute precision as given.
	 */
	public static function date_range_where( string $column, string $raw_from, string $raw_to ): ?array {
		$fragments = array();
		$args      = array();

		$from = self::normalise_datetime( $raw_from, '00:00:00' );
		if ( null !== $from ) {
			$fragments[] = "{$column} >= %s";
			$args[]      = $from;
		}

		$to = self::normalise_datetime( $raw_to, '23:59:59' );
		if ( null !== $to ) {
			$fragments[] = "{$column} <= %s";
			$args[]      = $to;
		}

		if ( empty( $fragments ) ) {
			return null;
		}

		return array(
			'sql'  => implode( ' AND ', $fragments ),
			'args' => $args,
		);
	}

	/**
	 * Accepts `Y-m-d` (defaults to $default_time) or the native `datetime-local`
	 * format `Y-m-d\TH:i` (defaults seconds to :00). Returns a MySQL
	 * `Y-m-d H:i:s` string, or null when $raw doesn't match either shape.
	 */
	private static function normalise_datetime( string $raw, string $default_time ): ?string {
		$raw = trim( $raw );
		if ( '' === $raw ) {
			return null;
		}

		if ( preg_match( '/^(\d{4}-\d{2}-\d{2})$/', $raw, $m ) ) {
			return $m[1] . ' ' . $default_time;
		}

		if ( preg_match( '/^(\d{4}-\d{2}-\d{2})[T ](\d{2}:\d{2})(:\d{2})?$/', $raw, $m ) ) {
			return $m[1] . ' ' . $m[2] . ( $m[3] ?? ':00' );
		}

		return null;
	}

	// ── Rendering ────────────────────────────────────────────────────────────────

	/**
	 * Renders one sortable <th>. Clicking the currently active column flips its
	 * direction; clicking any other column jumps to that column's own
	 * default_dir. Always resets the page key to 1.
	 */
	public static function sort_header( string $label, string $sort_key, array $whitelist, array $resolved_sort, array $state_args, string $base_url, string $paged_key = 'paged' ): string {
		$is_active = ( $resolved_sort['key'] === $sort_key );

		if ( $is_active ) {
			$next_dir = ( 'ASC' === $resolved_sort['dir'] ) ? 'desc' : 'asc';
		} else {
			$next_dir = strtolower( (string) ( $whitelist[ $sort_key ]['default_dir'] ?? 'asc' ) );
		}

		$link_args = array_merge(
			$state_args,
			array(
				'sort'     => $sort_key,
				'dir'      => $next_dir,
				$paged_key => 1,
			)
		);

		$url   = add_query_arg( $link_args, $base_url );
		$arrow = '';
		if ( $is_active ) {
			$icon  = ( 'ASC' === $resolved_sort['dir'] ) ? 'arrow-up-alt2' : 'arrow-down-alt2';
			$arrow = ' <span class="dashicons dashicons-' . esc_attr( $icon ) . '" aria-hidden="true"></span>';
		}

		return '<th><a href="' . esc_url( $url ) . '">' . esc_html( $label ) . $arrow . '</a></th>';
	}

	/** Renders a shared Prev/Page X of Y/Next block, carrying $state_args forward. */
	public static function pagination( int $page_num, int $total_pages, array $state_args, string $base_url, string $paged_key = 'paged' ): string {
		if ( $total_pages <= 1 ) {
			return '';
		}

		$out = '<div class="tablenav bottom" style="margin-top:1em"><div class="tablenav-pages">';

		if ( $page_num > 1 ) {
			$prev_url = add_query_arg( array_merge( $state_args, array( $paged_key => $page_num - 1 ) ), $base_url );
			$out     .= '<a class="button" href="' . esc_url( $prev_url ) . '">&laquo; ' . esc_html__( 'Previous', 'vcns-security-automation-manager' ) . '</a>';
		}

		$out .= '<span style="margin:0 8px">' . sprintf(
			/* translators: 1: current page number, 2: total pages */
			esc_html__( 'Page %1$d of %2$d', 'vcns-security-automation-manager' ),
			$page_num,
			$total_pages
		) . '</span>';

		if ( $page_num < $total_pages ) {
			$next_url = add_query_arg( array_merge( $state_args, array( $paged_key => $page_num + 1 ) ), $base_url );
			$out     .= '<a class="button" href="' . esc_url( $next_url ) . '">' . esc_html__( 'Next', 'vcns-security-automation-manager' ) . ' &raquo;</a>';
		}

		$out .= '</div></div>';

		return $out;
	}
}
