<?php
/**
 * CSP source proposal, risk, decision, and suppression workflow.
 */

declare( strict_types=1 );

namespace WP_SAM\CSP;

use WP_SAM\Modules\Audit_Log;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class Policy_Change_Manager {

	private const HIGH_RISK_DIRECTIVES = array(
		'script-src',
		'script-src-elem',
		'script-src-attr',
		'style-src',
		'style-src-elem',
		'style-src-attr',
		'connect-src',
		'form-action',
		'frame-src',
		'worker-src',
	);

	private const MEDIUM_RISK_DIRECTIVES = array(
		'font-src',
		'img-src',
		'media-src',
		'manifest-src',
		'child-src',
	);

	private Audit_Log $audit;
	private Decision_Engine $decision_engine;
	private Automation_Config $automation_config;
	private ?Policy_Version_Manager $policy_versions;
	private int $automatic_changes_this_run = 0;

	public function __construct( Audit_Log $audit, ?Decision_Engine $decision_engine = null, ?Policy_Version_Manager $policy_versions = null, ?Automation_Config $automation_config = null ) {
		$this->audit             = $audit;
		$this->decision_engine   = $decision_engine ?? new Decision_Engine();
		$this->policy_versions   = $policy_versions;
		$this->automation_config = $automation_config ?? new Automation_Config();
	}

	/**
	 * Adds or refreshes a pending source proposal unless a prior admin decision suppresses it.
	 *
	 * @param array{directive:string,uri:string,scheme:string,host:string} $candidate Candidate source data.
	 * @return array{status:string,id:int,risk_level:string,risk_reason:string}
	 */
	public function propose_source(
		string $surface,
		array $candidate,
		string $owner_component,
		string $owner_type,
		string $notes = ''
	): array {
		global $wpdb;

		$surface   = $this->normalise_token( $surface, 32 );
		$directive = $this->normalise_directive( $candidate['directive'] ?? '' );
		$host      = $this->normalise_host( $candidate['host'] ?? '' );
		$scheme    = $this->normalise_token( $candidate['scheme'] ?? 'https', 16 );
		$uri       = esc_url_raw( (string) ( $candidate['uri'] ?? '' ) );

		if ( '' === $surface || '' === $directive || '' === $host ) {
			return array(
				'status'      => 'invalid',
				'id'          => 0,
				'risk_level'  => 'high',
				'risk_reason' => 'Missing surface, directive, or host.',
			);
		}

		$risk        = $this->classify_source_risk( $directive, $scheme, $host, $uri );
		$fingerprint = self::fingerprint( $surface, $directive, $host );

		if ( $this->is_suppressed( $surface, $directive, $host ) ) {
			$this->audit->log(
				'policy_change',
				'proposal_suppressed',
				"Skipped {$surface} {$directive} {$host}; previously rejected or reverted by an administrator.",
				'info'
			);
			return array(
				'status'      => 'suppressed',
				'id'          => 0,
				'risk_level'  => $risk['level'],
				'risk_reason' => $risk['reason'],
			);
		}

		$table = $wpdb->prefix . 'csp_source_inventory';
		$now   = current_time( 'mysql', true );

		$existing = $wpdb->get_row(
			$wpdb->prepare(
				// phpcs:ignore WordPress.DB.DirectDatabaseQuery,WordPress.DB.PreparedSQL.InterpolatedNotPrepared
				"SELECT id, approval_state, evidence_count FROM {$table} WHERE surface = %s AND directive = %s AND source_host = %s LIMIT 1",
				$surface,
				$directive,
				$host
			),
			ARRAY_A
		);

		if ( is_array( $existing ) && ! empty( $existing['id'] ) ) {
			$wpdb->update(
				$table,
				array(
					'source_uri'           => $uri,
					'source_scheme'        => $scheme,
					'owner_component'      => $this->normalise_token( $owner_component, 255 ),
					'owner_type'           => $this->normalise_token( $owner_type, 32 ),
					'last_seen_at'         => $now,
					'risk_level'           => $risk['level'],
					'risk_reason'          => $risk['reason'],
					'decision_fingerprint' => $fingerprint,
					'evidence_count'       => max( 1, (int) ( $existing['evidence_count'] ?? 1 ) ) + 1,
					'notes'                => sanitize_text_field( substr( $notes, 0, 512 ) ),
				),
				array( 'id' => (int) $existing['id'] ),
				array( '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%d', '%s' ),
				array( '%d' )
			);

			if ( 'pending' === (string) ( $existing['approval_state'] ?? '' ) && $this->maybe_auto_approve_source( (int) $existing['id'] ) ) {
				return array(
					'status'      => 'auto_approved',
					'id'          => (int) $existing['id'],
					'risk_level'  => $risk['level'],
					'risk_reason' => $risk['reason'],
				);
			}

			return array(
				'status'      => 'updated',
				'id'          => (int) $existing['id'],
				'risk_level'  => $risk['level'],
				'risk_reason' => $risk['reason'],
			);
		}

		$wpdb->insert(
			$table,
			array(
				'surface'              => $surface,
				'directive'            => $directive,
				'source_uri'           => $uri,
				'source_scheme'        => $scheme,
				'source_host'          => $host,
				'owner_component'      => $this->normalise_token( $owner_component, 255 ),
				'owner_type'           => $this->normalise_token( $owner_type, 32 ),
				'approval_state'       => 'pending',
				'first_seen_at'        => $now,
				'last_seen_at'         => $now,
				'notes'                => sanitize_text_field( substr( $notes, 0, 512 ) ),
				'risk_level'           => $risk['level'],
				'risk_reason'          => $risk['reason'],
				'decision_fingerprint' => $fingerprint,
				'evidence_count'       => 1,
			),
			array( '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%d' )
		);

		$severity = 'high' === $risk['level'] ? 'warning' : 'info';
		$this->audit->log(
			'policy_change',
			'source_proposed',
			"Proposed {$surface} {$directive} {$host} ({$risk['level']} risk: {$risk['reason']}).",
			$severity
		);

		$source_id = (int) ( $wpdb->insert_id ?? 0 );
		if ( $this->maybe_auto_approve_source( $source_id ) ) {
			return array(
				'status'      => 'auto_approved',
				'id'          => $source_id,
				'risk_level'  => $risk['level'],
				'risk_reason' => $risk['reason'],
			);
		}

		return array(
			'status'      => 'added',
			'id'          => $source_id,
			'risk_level'  => $risk['level'],
			'risk_reason' => $risk['reason'],
		);
	}

	public function approve_source( int $source_id, string $reason ): bool {
		return $this->decide_source( $source_id, 'approved', $reason, false );
	}

	public function reject_source( int $source_id, string $reason ): bool {
		return $this->decide_source( $source_id, 'rejected', $reason, true );
	}

	public function revert_source( int $source_id, string $reason ): bool {
		return $this->decide_source( $source_id, 'reverted', $reason, true );
	}

	public function undo_source_decision( int $source_id, string $reason ): bool {
		return $this->decide_source( $source_id, 'undone', $reason, false );
	}

	public function is_suppressed( string $surface, string $directive, string $host ): bool {
		global $wpdb;

		$table       = $wpdb->prefix . 'sam_policy_change_decisions';
		$fingerprint = self::fingerprint( $surface, $directive, $host );

		$latest = $wpdb->get_row(
			$wpdb->prepare(
				// phpcs:ignore WordPress.DB.DirectDatabaseQuery,WordPress.DB.PreparedSQL.InterpolatedNotPrepared
				"SELECT action, suppression_active FROM {$table} WHERE decision_fingerprint = %s ORDER BY id DESC LIMIT 1",
				$fingerprint
			),
			ARRAY_A
		);

		return is_array( $latest ) && ! empty( $latest['suppression_active'] );
	}

	public static function fingerprint( string $surface, string $directive, string $host ): string {
		return hash(
			'sha256',
			strtolower( trim( $surface ) ) . '|' . strtolower( trim( $directive ) ) . '|' . strtolower( trim( $host ) )
		);
	}

	/**
	 * @return array{level:string,reason:string}
	 */
	public function classify_source_risk( string $directive, string $scheme, string $host, string $uri = '' ): array {
		$result = $this->decision_engine->evaluate_source(
			array(
				'directive'      => $directive,
				'source_scheme'  => $scheme,
				'source_host'    => $host,
				'source_uri'     => $uri,
				'evidence_count' => 1,
			),
			array( 'mode' => 'manual' )
		);

		return array(
			'level'  => $result['risk'],
			'reason' => $result['summary'],
		);
	}

	private function decide_source( int $source_id, string $action, string $reason, bool $suppress, string $actor_type = 'administrator', ?int $actor_user_id = null ): bool {
		if ( $source_id <= 0 ) {
			return false;
		}

		$reason = $this->normalise_decision_reason( $reason );
		if ( '' === $reason ) {
			return false;
		}

		global $wpdb;
		$table = $wpdb->prefix . 'csp_source_inventory';

		$source = $wpdb->get_row(
			$wpdb->prepare(
				// phpcs:ignore WordPress.DB.DirectDatabaseQuery,WordPress.DB.PreparedSQL.InterpolatedNotPrepared
				"SELECT * FROM {$table} WHERE id = %d LIMIT 1",
				$source_id
			),
			ARRAY_A
		);

		if ( ! is_array( $source ) || empty( $source['id'] ) ) {
			return false;
		}

		$now     = current_time( 'mysql', true );
		$user_id = null !== $actor_user_id ? $actor_user_id : ( function_exists( 'get_current_user_id' ) ? (int) get_current_user_id() : 0 );
		$state   = match ( $action ) {
			'approved', 'auto_approved' => 'approved',
			'undone'                    => 'pending',
			default                     => 'denied',
		};
		$fingerprint = ! empty( $source['decision_fingerprint'] ) ? $source['decision_fingerprint'] : self::fingerprint( $source['surface'], $source['directive'], $source['source_host'] );
		$risk_level  = ! empty( $source['risk_level'] ) ? $source['risk_level'] : 'low';
		$risk_reason = ! empty( $source['risk_reason'] ) ? $source['risk_reason'] : '';

		$data    = array(
			'approval_state'       => $state,
			'last_decision'        => $action,
			'decision_reason'      => $reason,
			'decided_at'           => $now,
			'decided_by'           => $user_id,
			'decision_fingerprint' => $fingerprint,
		);
		$formats = array( '%s', '%s', '%s', '%s', '%d', '%s' );

		if ( 'approved' === $state ) {
			$data['approved_at'] = $now;
			$formats[]           = '%s';
		}

		if ( 'approved' !== $state ) {
			$data['approved_at'] = null;
			$formats[]           = '%s';
		}

		$updated = $wpdb->update(
			$table,
			$data,
			array( 'id' => $source_id ),
			$formats,
			array( '%d' )
		);

		if ( false === $updated ) {
			return false;
		}

		$automation          = $this->automation_config->for_surface( (string) $source['surface'] );
		$deterministic       = $this->decision_engine->evaluate_source( $source, $automation );
		$previous_version_id = $this->latest_policy_version_id( (string) $source['surface'] );
		$policy_version_id   = 0;
		if ( in_array( $action, array( 'approved', 'auto_approved', 'reverted' ), true ) || ( 'undone' === $action && 'approved' === ( $source['approval_state'] ?? '' ) ) ) {
			$policy_version_id = $this->policy_versions()->capture_snapshot( (string) $source['surface'], 'decision', $source_id );
		}
		$undone_decision_id = 'undone' === $action ? $this->latest_decision_id( $fingerprint ) : 0;

		$decision_id = $this->record_decision(
			$source,
			$action,
			$fingerprint,
			$deterministic['risk'],
			$deterministic['summary'],
			$reason,
			$suppress,
			$now,
			$user_id,
			$deterministic,
			$previous_version_id,
			$policy_version_id,
			$undone_decision_id,
			$actor_type
		);
		if ( $decision_id <= 0 ) {
			return false;
		}

		$this->record_rule_evaluations( $source_id, $decision_id, $deterministic, $now );

		$this->audit->log(
			'policy_change',
			"source_{$action}",
			'automation_engine' === $actor_type
				? "Automation engine {$action} {$source['surface']} {$source['directive']} {$source['source_host']}."
				: "Administrator {$action} {$source['surface']} {$source['directive']} {$source['source_host']}.",
			in_array( $action, array( 'reverted', 'rejected', 'undone' ), true ) ? 'warning' : 'info'
		);

		return true;
	}

	private function record_decision(
		array $source,
		string $action,
		string $fingerprint,
		string $risk_level,
		string $risk_reason,
		string $reason,
		bool $suppress,
		string $now,
		int $user_id,
		array $deterministic,
		int $previous_policy_version_id,
		int $policy_version_id,
		int $reverted_decision_id = 0,
		string $actor_type = 'administrator'
	): int {
		global $wpdb;

		$state = match ( $action ) {
			'approved'      => 'approved',
			'auto_approved' => 'auto_approved',
			'rejected'      => 'rejected',
			'reverted'      => 'reverted',
			'undone'        => 'pending',
			default         => 'pending',
		};
		$previous_policy_version_value = $previous_policy_version_id > 0 ? (string) $previous_policy_version_id : null;
		$policy_version_value          = $policy_version_id > 0 ? (string) $policy_version_id : null;
		$reverted_decision_value       = $reverted_decision_id > 0 ? $reverted_decision_id : null;

		$inserted = $wpdb->insert(
			$wpdb->prefix . 'sam_policy_change_decisions',
			array(
				'change_type'                => 'source',
				'source_inventory_id'        => (int) ( $source['id'] ?? 0 ),
				'surface'                    => $source['surface'],
				'directive'                  => $source['directive'],
				'source_host'                => $source['source_host'],
				'source_uri'                 => $source['source_uri'],
				'decision_fingerprint'       => $fingerprint,
				'action'                     => $action,
				'state'                      => $state,
				'risk_level'                 => $risk_level,
				'risk_reason'                => $risk_reason,
				'reason'                     => sanitize_text_field( substr( $reason, 0, 512 ) ),
				'user_id'                    => $user_id,
				'actor_type'                 => $this->normalise_actor_type( $actor_type ),
				'actor_id'                   => $user_id > 0 ? (string) $user_id : null,
				'previous_policy_version_id' => $previous_policy_version_value,
				'policy_version_id'          => $policy_version_value,
				'decision_engine_version'    => $deterministic['engine_version'],
				'deterministic_result'       => wp_json_encode( $deterministic ),
				'evidence_snapshot'          => wp_json_encode( $this->source_evidence_snapshot( $source ) ),
				'reverted_decision_id'       => $reverted_decision_value,
				'software_version'           => defined( 'WP_SAM_VERSION' ) ? WP_SAM_VERSION : '',
				'suppression_active'         => $suppress ? 1 : 0,
				'created_at'                 => $now,
			),
			array( '%s', '%d', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%d', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%d', '%s', '%d', '%s' )
		);

		if ( false === $inserted ) {
			return 0;
		}

		return (int) ( $wpdb->insert_id ?? 0 );
	}

	private function maybe_auto_approve_source( int $source_id ): bool {
		if ( $source_id <= 0 ) {
			return false;
		}

		global $wpdb;
		$table  = $wpdb->prefix . 'csp_source_inventory';
		$source = $wpdb->get_row(
			$wpdb->prepare(
				// phpcs:ignore WordPress.DB.DirectDatabaseQuery,WordPress.DB.PreparedSQL.InterpolatedNotPrepared
				"SELECT * FROM {$table} WHERE id = %d LIMIT 1",
				$source_id
			),
			ARRAY_A
		);

		if ( ! is_array( $source ) || 'pending' !== (string) ( $source['approval_state'] ?? '' ) ) {
			return false;
		}

		$automation = $this->automation_config->for_surface( (string) $source['surface'] );
		if ( ! $this->automation_config_allows_source( $source, $automation ) ) {
			return false;
		}

		$deterministic = $this->decision_engine->evaluate_source( $source, $automation );
		if ( empty( $deterministic['automation_eligible'] ) ) {
			return false;
		}

		if ( ! $this->auto_approve_source( $source_id ) ) {
			return false;
		}

		++$this->automatic_changes_this_run;
		return true;
	}

	private function auto_approve_source( int $source_id ): bool {
		return $this->decide_source(
			$source_id,
			'auto_approved',
			'Automatically approved by the deterministic CSP automation engine.',
			false,
			'automation_engine',
			0
		);
	}

	private function automation_config_allows_source( array $source, array $automation ): bool {
		$mode = (string) ( $automation['mode'] ?? 'manual' );
		if ( Automation_Config::MODE_MANUAL === $mode || ! Automation_Mode_Registry::is_valid_mode( $mode ) ) {
			return false;
		}

		$max_changes = (int) ( $automation['max_automatic_changes_per_scan'] ?? 0 );
		if ( $max_changes <= 0 || $this->automatic_changes_this_run >= $max_changes ) {
			return false;
		}

		if ( ! empty( $automation['require_ai_agreement'] ) ) {
			return false;
		}

		$directive = strtolower( (string) ( $source['directive'] ?? '' ) );
		$scheme    = strtolower( (string) ( $source['source_scheme'] ?? '' ) );

		$excluded_directives = is_array( $automation['excluded_directives'] ?? null ) ? $automation['excluded_directives'] : array();
		if ( in_array( $directive, $excluded_directives, true ) ) {
			return false;
		}

		$enabled_directives = is_array( $automation['enabled_directives'] ?? null ) ? $automation['enabled_directives'] : array();
		if ( ! empty( $enabled_directives ) && ! in_array( $directive, $enabled_directives, true ) ) {
			return false;
		}

		$allowed_schemes = is_array( $automation['allowed_source_schemes'] ?? null ) ? $automation['allowed_source_schemes'] : array();
		return empty( $allowed_schemes ) || in_array( $scheme, $allowed_schemes, true );
	}

	private function record_rule_evaluations( int $source_id, int $decision_id, array $deterministic, string $now ): void {
		global $wpdb;

		foreach ( $deterministic['findings'] ?? array() as $finding ) {
			if ( ! is_array( $finding ) ) {
				continue;
			}
			$wpdb->insert(
				$wpdb->prefix . 'sam_decision_rule_evaluations',
				array(
					'proposal_id'       => $source_id,
					'decision_id'       => $decision_id > 0 ? $decision_id : null,
					'engine_version'    => (string) $deterministic['engine_version'],
					'rule_id'           => (string) ( $finding['rule_id'] ?? '' ),
					'rule_version'      => (string) ( $finding['rule_version'] ?? '1' ),
					'result'            => (string) ( $finding['result'] ?? 'review' ),
					'risk_effect'       => (string) ( $finding['risk_effect'] ?? '' ),
					'automation_effect' => (string) ( $finding['automation_effect'] ?? '' ),
					'explanation'       => sanitize_text_field( substr( (string) ( $finding['explanation'] ?? '' ), 0, 512 ) ),
					'created_at'        => $now,
				),
				array( '%d', '%d', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s' )
			);
		}
	}

	private function latest_policy_version_id( string $surface ): int {
		$latest = $this->policy_versions()->latest_version( $surface );
		return isset( $latest['id'] ) ? (int) $latest['id'] : 0;
	}

	private function latest_decision_id( string $fingerprint ): int {
		global $wpdb;

		$table = $wpdb->prefix . 'sam_policy_change_decisions';
		return (int) $wpdb->get_var(
			$wpdb->prepare(
				// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
				"SELECT id FROM {$table} WHERE decision_fingerprint = %s ORDER BY id DESC LIMIT 1",
				$fingerprint
			)
		);
	}

	private function policy_versions(): Policy_Version_Manager {
		if ( null === $this->policy_versions ) {
			$this->policy_versions = new Policy_Version_Manager();
		}
		return $this->policy_versions;
	}

	private function source_evidence_snapshot( array $source ): array {
		return array(
			'source_inventory_id' => (int) ( $source['id'] ?? 0 ),
			'surface'             => (string) ( $source['surface'] ?? '' ),
			'directive'           => (string) ( $source['directive'] ?? '' ),
			'source_host'         => (string) ( $source['source_host'] ?? '' ),
			'source_uri'          => (string) ( $source['source_uri'] ?? '' ),
			'first_seen_at'       => (string) ( $source['first_seen_at'] ?? '' ),
			'last_seen_at'        => (string) ( $source['last_seen_at'] ?? '' ),
			'evidence_count'      => (int) ( $source['evidence_count'] ?? 1 ),
			'owner_component'     => (string) ( $source['owner_component'] ?? '' ),
			'owner_type'          => (string) ( $source['owner_type'] ?? '' ),
		);
	}

	private function normalise_directive( string $directive ): string {
		$directive = strtolower( trim( sanitize_text_field( $directive ) ) );
		return substr( $directive, 0, 64 );
	}

	private function normalise_host( string $host ): string {
		$host = strtolower( trim( sanitize_text_field( $host ) ) );
		return substr( $host, 0, 255 );
	}

	private function normalise_token( string $token, int $length ): string {
		return substr( strtolower( trim( sanitize_text_field( $token ) ) ), 0, $length );
	}

	private function normalise_decision_reason( string $reason ): string {
		return sanitize_text_field( substr( trim( $reason ), 0, 512 ) );
	}

	private function normalise_actor_type( string $actor_type ): string {
		return in_array( $actor_type, array( 'administrator', 'automation_engine', 'system_migration', 'system_recovery' ), true ) ? $actor_type : 'administrator';
	}
}
