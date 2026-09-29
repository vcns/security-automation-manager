<?php
/**
 * CRUD, validation, and lifecycle for controlled, time-bound weakenings of a
 * control/surface (`sam_exceptions`, GitHub issue #177) -- a legacy
 * integration or third-party embed that genuinely needs a control relaxed
 * for a while, handled as an auditable, expiring exception rather than a
 * silent, permanent override.
 *
 * Modeled directly on Custom_Rule_Store's create()/update()/delete()/save()
 * shape, with two deliberate differences suited to what an exception is:
 *
 * - No hard delete. An exception is either still active, has expired on its
 *   own (expire_overdue(), run by Exception_Scheduler's daily cron), or was
 *   deliberately revoke()'d early -- all three are states of the same row,
 *   never a removed one, so "preserve the full decision history" (the
 *   roadmap's own requirement) holds without a separate ledger table.
 * - Every state change beyond initial creation (extend(), revoke(),
 *   automatic expiry) is also written to Audit_Log, since those are the
 *   moments this table's own "current state only" design would otherwise
 *   lose the story of what happened and why.
 */

declare( strict_types=1 );

namespace WP_SAM\Intelligence;

use WP_SAM\Modules\Audit_Log;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Exception_Store {

	public const VALID_RISK_LEVELS = array( 'low', 'medium', 'high' );
	public const STATUS_ACTIVE     = 'active';
	public const STATUS_EXPIRED    = 'expired';
	public const STATUS_REVOKED    = 'revoked';

	private Audit_Log $audit;

	/**
	 * Constructor.
	 *
	 * @param Audit_Log|null $audit Audit log, a new one is created when omitted.
	 */
	public function __construct( ?Audit_Log $audit = null ) {
		$this->audit = null !== $audit ? $audit : new Audit_Log();
	}

	/** @return array<int, array<string, mixed>> every stored exception, most recently created first. */
	public function all(): array {
		global $wpdb;
		$table = $wpdb->prefix . 'sam_exceptions';
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		$rows = $wpdb->get_results( "SELECT * FROM {$table} ORDER BY id DESC", ARRAY_A );
		return ! empty( $rows ) ? $rows : array();
	}

	/** @return array<string, mixed>|null */
	public function get( int $id ): ?array {
		global $wpdb;
		$table = $wpdb->prefix . 'sam_exceptions';
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		$row = $wpdb->get_row( $wpdb->prepare( "SELECT * FROM {$table} WHERE id = %d", $id ), ARRAY_A );
		return is_array( $row ) ? $row : null;
	}

	/**
	 * True when an active, non-expired, non-revoked exception exists for
	 * $control on $surface -- the query a promotion gate (GitHub issue
	 * #179) or a posture-score row (issue #175) needs, so both can be built
	 * against this rather than re-deriving the same "is this one currently
	 * in force" logic independently.
	 */
	public function has_active_for( string $control, string $surface ): bool {
		global $wpdb;
		$table = $wpdb->prefix . 'sam_exceptions';
		$now   = current_time( 'mysql', true );

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching
		$count = (int) $wpdb->get_var(
			$wpdb->prepare(
				// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
				"SELECT COUNT(*) FROM {$table}
				WHERE control = %s AND surface = %s AND review_status = %s
				AND (expiry_date IS NULL OR expiry_date > %s)",
				$control,
				$surface,
				self::STATUS_ACTIVE,
				$now
			)
		);

		return $count > 0;
	}

	/**
	 * Validates and inserts a new exception. A reason (business
	 * justification) and an expiry date are mandatory unless
	 * $input['is_privileged_override'] is truthy, matching the roadmap's
	 * "require a reason" / "require an expiry unless a privileged override
	 * is used" rules.
	 *
	 * @param array<string,mixed> $input Raw, unsanitised admin input.
	 * @return array{success: bool, id: int, errors: array<int,string>}
	 */
	public function create( array $input ): array {
		$errors = array();

		$control = sanitize_key( (string) ( $input['control'] ?? '' ) );
		if ( '' === $control ) {
			$errors[] = __( 'Affected control is required.', 'vcns-security-automation-manager' );
		}

		$surface = sanitize_key( (string) ( $input['surface'] ?? '' ) );

		$weaker_value = sanitize_textarea_field( (string) ( $input['weaker_value'] ?? '' ) );
		if ( '' === $weaker_value ) {
			$errors[] = __( 'The requested weaker value is required.', 'vcns-security-automation-manager' );
		}

		$business_justification = sanitize_textarea_field( (string) ( $input['business_justification'] ?? '' ) );
		if ( '' === $business_justification ) {
			$errors[] = __( 'A business justification (reason) is required.', 'vcns-security-automation-manager' );
		}

		$owner = sanitize_text_field( (string) ( $input['owner'] ?? '' ) );
		if ( '' === $owner ) {
			$errors[] = __( 'An owner is required.', 'vcns-security-automation-manager' );
		}

		$is_privileged_override = ! empty( $input['is_privileged_override'] );

		$expiry_date = sanitize_text_field( (string) ( $input['expiry_date'] ?? '' ) );
		if ( '' !== $expiry_date && false === strtotime( $expiry_date ) ) {
			$errors[]    = __( 'Expiry date is not a valid date.', 'vcns-security-automation-manager' );
			$expiry_date = '';
		}
		if ( '' === $expiry_date && ! $is_privileged_override ) {
			$errors[] = __( 'An expiry date is required unless a privileged override is used.', 'vcns-security-automation-manager' );
		}

		$risk_classification = sanitize_key( (string) ( $input['risk_classification'] ?? '' ) );
		if ( ! in_array( $risk_classification, self::VALID_RISK_LEVELS, true ) ) {
			$risk_classification = 'medium';
		}

		if ( ! empty( $errors ) ) {
			return array(
				'success' => false,
				'id'      => 0,
				'errors'  => $errors,
			);
		}

		global $wpdb;
		$table = $wpdb->prefix . 'sam_exceptions';
		$now   = current_time( 'mysql', true );

		$start_date = sanitize_text_field( (string) ( $input['start_date'] ?? '' ) );
		if ( '' === $start_date || false === strtotime( $start_date ) ) {
			$start_date = $now;
		}

		$data = array(
			'control'                 => $control,
			'surface'                 => $surface,
			'weaker_value'            => $weaker_value,
			'business_justification'  => $business_justification,
			'technical_justification' => sanitize_textarea_field( (string) ( $input['technical_justification'] ?? '' ) ),
			'owner'                   => $owner,
			'approver'                => sanitize_text_field( (string) ( $input['approver'] ?? '' ) ),
			'compensating_control'    => sanitize_textarea_field( (string) ( $input['compensating_control'] ?? '' ) ),
			'risk_classification'     => $risk_classification,
			'reference'               => sanitize_text_field( (string) ( $input['reference'] ?? '' ) ),
			'is_privileged_override'  => $is_privileged_override ? 1 : 0,
			'review_status'           => self::STATUS_ACTIVE,
			'start_date'              => $start_date,
			'expiry_date'             => '' !== $expiry_date ? gmdate( 'Y-m-d H:i:s', (int) strtotime( $expiry_date ) ) : null,
			'created_at'              => $now,
			'updated_at'              => $now,
		);

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching
		$result = $wpdb->insert( $table, $data );
		$id     = false !== $result ? (int) $wpdb->insert_id : 0;

		if ( $id > 0 ) {
			$this->audit->log(
				'exceptions',
				'exception_created',
				sprintf( 'Exception #%1$d created for %2$s/%3$s by %4$s: %5$s', $id, $control, '' !== $surface ? $surface : 'all surfaces', $owner, $business_justification )
			);
		}

		return array(
			'success' => $id > 0,
			'id'      => $id,
			'errors'  => array(),
		);
	}

	/**
	 * Extends an active exception's expiry date. A reason is mandatory --
	 * "do not silently extend an exception" and "record all extensions" are
	 * both roadmap requirements, satisfied by requiring $reason here and
	 * always writing an audit event, never by the row's own history alone.
	 *
	 * @return array{success: bool, errors: array<int,string>}
	 */
	public function extend( int $id, string $new_expiry_date, string $reason ): array {
		$reason = sanitize_textarea_field( $reason );
		if ( '' === $reason ) {
			return array(
				'success' => false,
				'errors'  => array( __( 'A reason is required to extend an exception.', 'vcns-security-automation-manager' ) ),
			);
		}

		$timestamp = strtotime( $new_expiry_date );
		if ( false === $timestamp ) {
			return array(
				'success' => false,
				'errors'  => array( __( 'New expiry date is not a valid date.', 'vcns-security-automation-manager' ) ),
			);
		}

		$existing = $this->get( $id );
		if ( null === $existing || self::STATUS_ACTIVE !== $existing['review_status'] ) {
			return array(
				'success' => false,
				'errors'  => array( __( 'Only an active exception can be extended.', 'vcns-security-automation-manager' ) ),
			);
		}

		global $wpdb;
		$table = $wpdb->prefix . 'sam_exceptions';
		$now   = current_time( 'mysql', true );

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching
		$wpdb->update(
			$table,
			array(
				'expiry_date' => gmdate( 'Y-m-d H:i:s', $timestamp ),
				'updated_at'  => $now,
			),
			array( 'id' => $id )
		);

		$this->audit->log(
			'exceptions',
			'exception_extended',
			sprintf( 'Exception #%1$d extended to %2$s: %3$s', $id, gmdate( 'Y-m-d H:i:s', $timestamp ), $reason )
		);

		return array(
			'success' => true,
			'errors'  => array(),
		);
	}

	/**
	 * Revokes an active exception immediately -- "allow immediate
	 * revocation" is a roadmap requirement. A reason is required for the
	 * same auditability reason extend() requires one.
	 *
	 * @return array{success: bool, errors: array<int,string>}
	 */
	public function revoke( int $id, string $reason, string $revoked_by ): array {
		$reason = sanitize_textarea_field( $reason );
		if ( '' === $reason ) {
			return array(
				'success' => false,
				'errors'  => array( __( 'A reason is required to revoke an exception.', 'vcns-security-automation-manager' ) ),
			);
		}

		$existing = $this->get( $id );
		if ( null === $existing || self::STATUS_ACTIVE !== $existing['review_status'] ) {
			return array(
				'success' => false,
				'errors'  => array( __( 'Only an active exception can be revoked.', 'vcns-security-automation-manager' ) ),
			);
		}

		global $wpdb;
		$table = $wpdb->prefix . 'sam_exceptions';
		$now   = current_time( 'mysql', true );

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching
		$wpdb->update(
			$table,
			array(
				'review_status' => self::STATUS_REVOKED,
				'revoked_at'    => $now,
				'revoked_by'    => sanitize_text_field( $revoked_by ),
				'updated_at'    => $now,
			),
			array( 'id' => $id )
		);

		$this->audit->log(
			'exceptions',
			'exception_revoked',
			sprintf( 'Exception #%1$d revoked by %2$s: %3$s', $id, $revoked_by, $reason )
		);

		return array(
			'success' => true,
			'errors'  => array(),
		);
	}

	/**
	 * Flips every active exception past its expiry_date to 'expired' --
	 * "return expired exceptions to review rather than silently continuing"
	 * is a roadmap requirement. Called by Exception_Scheduler's daily cron.
	 * Privileged overrides (expiry_date IS NULL) never expire on their own.
	 *
	 * @return int Number of exceptions flipped to expired.
	 */
	public function expire_overdue(): int {
		global $wpdb;
		$table = $wpdb->prefix . 'sam_exceptions';
		$now   = current_time( 'mysql', true );

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching
		$overdue = $wpdb->get_results(
			$wpdb->prepare(
				// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
				"SELECT id FROM {$table} WHERE review_status = %s AND expiry_date IS NOT NULL AND expiry_date <= %s",
				self::STATUS_ACTIVE,
				$now
			),
			ARRAY_A
		);

		if ( empty( $overdue ) ) {
			return 0;
		}

		foreach ( $overdue as $row ) {
			$id = (int) $row['id'];
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching
			$wpdb->update(
				$table,
				array(
					'review_status' => self::STATUS_EXPIRED,
					'updated_at'    => $now,
				),
				array( 'id' => $id )
			);
			$this->audit->log( 'exceptions', 'exception_expired', sprintf( 'Exception #%d expired and returned to review.', $id ) );
		}

		return count( $overdue );
	}

	/**
	 * Active exceptions expiring within $window_days -- "notify
	 * administrators before expiry" is a roadmap requirement. Called by
	 * Exception_Scheduler's daily cron to decide what to email about.
	 *
	 * @return array<int, array<string, mixed>>
	 */
	public function due_for_notice( int $window_days ): array {
		global $wpdb;
		$table   = $wpdb->prefix . 'sam_exceptions';
		$now     = current_time( 'mysql', true );
		$horizon = gmdate( 'Y-m-d H:i:s', time() + ( $window_days * DAY_IN_SECONDS ) );

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching
		$rows = $wpdb->get_results(
			$wpdb->prepare(
				// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
				"SELECT * FROM {$table}
				WHERE review_status = %s AND expiry_date IS NOT NULL
				AND expiry_date > %s AND expiry_date <= %s
				ORDER BY expiry_date ASC",
				self::STATUS_ACTIVE,
				$now,
				$horizon
			),
			ARRAY_A
		);

		return ! empty( $rows ) ? $rows : array();
	}
}
