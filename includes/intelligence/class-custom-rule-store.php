<?php
/**
 * CRUD and validation for admin-authored custom regex detection rules
 * (`sam_custom_detector_rules`) -- the storage half of Custom_Rule_
 * Detector, this plugin's fail2ban-style custom filter feature.
 *
 * Validation happens once, here, at save time -- never re-validated on
 * every request, since Custom_Rule_Detector trusts whatever is already
 * in the table (matching how every other admin-configured store in this
 * codebase works, e.g. Referrer_Policy_Builder::sanitize_value()).
 *
 * Regex safety: a rule's pattern is required to actually compile
 * (rejected at save time otherwise, so a typo fails loudly rather than
 * silently matching nothing forever) and capped at MAX_PATTERN_LENGTH.
 * This plugin does not attempt to detect or reject a pathologically
 * slow-but-valid pattern (e.g. catastrophic backtracking) -- doing that
 * reliably would need either a real regex-complexity analyser or an
 * out-of-process match with a hard wall-clock timeout, neither of which
 * exists here. PHP's own pcre.backtrack_limit/pcre.recursion_limit ini
 * settings already bound a single preg_match() call's worst case (it
 * fails rather than hanging indefinitely), the same backstop every
 * other Pattern_Detector subclass in this codebase already relies on.
 * A rule is only ever authored by a manage_options administrator, the
 * same trust level already required to write a raw CSP directive
 * override or a Bypass Best Practices toggle -- this is documented risk
 * an admin opts into per rule, not something exposed to request input.
 */

declare( strict_types=1 );

namespace WP_SAM\Intelligence;

use WP_SAM\Intelligence\Detectors\Custom_Rule_Detector;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Custom_Rule_Store {

	public const MAX_PATTERN_LENGTH = 500;
	public const MAX_NAME_LENGTH    = 128;

	/** @return array<int, array<string, mixed>> every stored rule, most recently created first. */
	public function all(): array {
		global $wpdb;
		$table = $wpdb->prefix . 'sam_custom_detector_rules';
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		$rows = $wpdb->get_results( "SELECT * FROM {$table} ORDER BY id DESC", ARRAY_A );
		return ! empty( $rows ) ? $rows : array();
	}

	/** @return array<string, mixed>|null */
	public function get( int $id ): ?array {
		global $wpdb;
		$table = $wpdb->prefix . 'sam_custom_detector_rules';
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		$row = $wpdb->get_row( $wpdb->prepare( "SELECT * FROM {$table} WHERE id = %d", $id ), ARRAY_A );
		return is_array( $row ) ? $row : null;
	}

	/**
	 * Validates and inserts a new rule.
	 *
	 * @param array<string,mixed> $input Raw, unsanitised admin input.
	 * @return array{success: bool, id: int, errors: array<int,string>}
	 */
	public function create( array $input ): array {
		return $this->save( null, $input );
	}

	/**
	 * Validates and updates an existing rule.
	 *
	 * @param array<string,mixed> $input Raw, unsanitised admin input.
	 * @return array{success: bool, id: int, errors: array<int,string>}
	 */
	public function update( int $id, array $input ): array {
		return $this->save( $id, $input );
	}

	public function delete( int $id ): bool {
		global $wpdb;
		$table = $wpdb->prefix . 'sam_custom_detector_rules';
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching
		$result = $wpdb->query(
			$wpdb->prepare(
				// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
				"DELETE FROM {$table} WHERE id = %d",
				$id
			)
		);
		return false !== $result;
	}

	/**
	 * Compiles $pattern against $sample without persisting anything --
	 * the "test this rule" tool on the admin page. Returns null (rather
	 * than throwing) for an invalid pattern, same as a failed preg_match().
	 */
	public function test( string $pattern, string $sample ): ?bool {
		if ( '' === trim( $pattern ) || strlen( $pattern ) > self::MAX_PATTERN_LENGTH || ! self::pattern_compiles( $pattern ) ) {
			return null;
		}
		// phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- pattern_compiles() already proved this preg_match() won't warn.
		return 1 === @preg_match( $pattern, $sample );
	}

	/**
	 * @param array<string,mixed> $input
	 * @return array{success: bool, id: int, errors: array<int,string>}
	 */
	private function save( ?int $id, array $input ): array {
		$errors = array();

		$name = sanitize_text_field( (string) ( $input['name'] ?? '' ) );
		if ( '' === $name ) {
			$errors[] = __( 'Name is required.', 'vcns-security-automation-manager' );
		} elseif ( strlen( $name ) > self::MAX_NAME_LENGTH ) {
			$errors[] = sprintf(
				/* translators: %d: maximum character length */
				__( 'Name must be %d characters or fewer.', 'vcns-security-automation-manager' ),
				self::MAX_NAME_LENGTH
			);
		}

		$pattern = (string) ( $input['pattern'] ?? '' );
		if ( '' === trim( $pattern ) ) {
			$errors[] = __( 'Pattern is required.', 'vcns-security-automation-manager' );
		} elseif ( strlen( $pattern ) > self::MAX_PATTERN_LENGTH ) {
			$errors[] = sprintf(
				/* translators: %d: maximum character length */
				__( 'Pattern must be %d characters or fewer.', 'vcns-security-automation-manager' ),
				self::MAX_PATTERN_LENGTH
			);
		} elseif ( ! self::pattern_compiles( $pattern ) ) {
			$errors[] = __( 'Pattern is not a valid PHP regular expression (it must include delimiters, e.g. "/foo/i").', 'vcns-security-automation-manager' );
		}

		$subject_field = sanitize_key( (string) ( $input['subject_field'] ?? '' ) );
		if ( ! in_array( $subject_field, Custom_Rule_Detector::VALID_SUBJECT_FIELDS, true ) ) {
			$subject_field = 'request_uri';
		}

		$severity = sanitize_key( (string) ( $input['severity'] ?? '' ) );
		if ( ! in_array( $severity, Custom_Rule_Detector::VALID_SEVERITIES, true ) ) {
			$severity = 'medium';
		}

		$valid_surfaces = array( 'frontend', 'admin', 'login', 'api' );
		$requested      = is_array( $input['surfaces'] ?? null ) ? $input['surfaces'] : array();
		$surfaces       = array_values( array_intersect( $valid_surfaces, array_map( 'sanitize_key', $requested ) ) );
		// Every valid surface selected is the same as none selected (Detector::
		// applicable_surfaces()'s own "empty means every surface" contract) --
		// storing it as empty here keeps a rule the admin means to apply
		// everywhere behaving identically whether or not a surface is added later.
		if ( count( $surfaces ) === count( $valid_surfaces ) ) {
			$surfaces = array();
		}

		$description = sanitize_textarea_field( (string) ( $input['description'] ?? '' ) );

		if ( ! empty( $errors ) ) {
			return array(
				'success' => false,
				'id'      => $id ?? 0,
				'errors'  => $errors,
			);
		}

		global $wpdb;
		$table = $wpdb->prefix . 'sam_custom_detector_rules';
		$now   = current_time( 'mysql', true );

		$data = array(
			'name'          => $name,
			'pattern'       => $pattern,
			'subject_field' => $subject_field,
			'severity'      => $severity,
			'surfaces'      => wp_json_encode( $surfaces ),
			'description'   => $description,
			'updated_at'    => $now,
		);

		if ( null !== $id ) {
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching
			$result = $wpdb->update( $table, $data, array( 'id' => $id ) );
			return array(
				'success' => false !== $result,
				'id'      => $id,
				'errors'  => array(),
			);
		}

		$data['created_at'] = $now;
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching
		$result = $wpdb->insert( $table, $data );

		return array(
			'success' => false !== $result,
			'id'      => false !== $result ? (int) $wpdb->insert_id : 0,
			'errors'  => array(),
		);
	}

	private static function pattern_compiles( string $pattern ): bool {
		// phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- deliberately probing whether $pattern is a valid PCRE; a warning here is the expected way PHP reports an invalid one.
		return false !== @preg_match( $pattern, '' );
	}
}
