<?php
/**
 * One admin-authored, database-stored regex rule -- Phase 4C extension
 * (fail2ban-style custom filters, requested alongside the bot/crawler
 * classification work). One instance per row in Custom_Rule_Store;
 * Plugin::register_detectors() constructs and registers one per stored
 * rule on every request, the same way register_defaults() registers the
 * 13 built-in §11 families.
 *
 * Deliberately reuses Pattern_Detector rather than inventing a parallel
 * matching mechanism: a custom rule is exactly a single-entry rules()
 * list, so all of Pattern_Detector's decoding, subject-length capping,
 * and severity handling apply unchanged. It also means a custom rule
 * flows through the exact same Detector_Policy_Store / Detector_Engine /
 * Traffic_Block_Store pipeline as every built-in family -- no new
 * blocking path, same observe-by-default posture, and it shows up
 * automatically on the existing Detectors tab (Traffic Controls ->
 * Detectors) for enable/control-action management, with no admin UI
 * changes needed there.
 *
 * Regex safety: PHP's own pcre.backtrack_limit/pcre.recursion_limit ini
 * settings already bound a single preg_match() call's worst-case cost
 * (a match that exceeds either simply fails rather than hanging
 * forever), the same backstop every other Pattern_Detector subclass in
 * this codebase relies on. Custom_Rule_Store additionally caps pattern
 * length and requires it to compile at save time -- see that class's
 * own docblock for the full reasoning, including why this plugin does
 * not attempt to sandbox or time-box an individual preg_match() call.
 */

declare( strict_types=1 );

namespace WP_SAM\Intelligence\Detectors;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class Custom_Rule_Detector extends Pattern_Detector {

	public const VALID_SEVERITIES = array( 'low', 'medium', 'high', 'critical' );

	/**
	 * request_uri matches Sql_Injection_Detector/Html_Injection_Detector's
	 * own subject() convention exactly (path, plus '?query' when present) --
	 * the most broadly useful default for a fail2ban-style path/URI filter.
	 */
	public const VALID_SUBJECT_FIELDS = array( 'request_uri', 'path', 'query_string', 'user_agent' );

	/** @var array<string,mixed> */
	private array $rule;

	/** @param array<string,mixed> $rule A row from Custom_Rule_Store. */
	public function __construct( array $rule ) {
		$this->rule = $rule;
	}

	public function id(): string {
		return 'custom_' . (int) $this->rule['id'];
	}

	public function family(): string {
		return 'custom';
	}

	public function applicable_surfaces(): array {
		$surfaces = json_decode( (string) ( $this->rule['surfaces'] ?? '' ), true );
		return is_array( $surfaces ) ? array_values( array_filter( $surfaces, 'is_string' ) ) : array();
	}

	public function allowed_control_actions(): array {
		// An admin who took the trouble to author this rule is making an
		// explicit, informed decision -- same reasoning §11.4/§11.13 use for
		// making HTML Injection/Legacy Endpoints the first enforce-capable
		// built-in families. Still defaults to observe (default_control_
		// action() below); enforce is opt-in via the Detectors tab exactly
		// like every other enforce-capable family, not automatic here.
		return array( 'observe', 'enforce' );
	}

	public function default_control_action(): string {
		return 'observe';
	}

	protected function rules(): array {
		$severity = in_array( $this->rule['severity'] ?? '', self::VALID_SEVERITIES, true )
			? (string) $this->rule['severity']
			: 'medium';

		return array(
			array(
				'id'          => $this->id(),
				'pattern'     => (string) $this->rule['pattern'],
				'severity'    => $severity,
				'description' => (string) ( $this->rule['name'] ?? '' ),
			),
		);
	}

	protected function subject( array $context ): string {
		$field = in_array( $this->rule['subject_field'] ?? '', self::VALID_SUBJECT_FIELDS, true )
			? (string) $this->rule['subject_field']
			: 'request_uri';

		$path         = (string) ( $context['path'] ?? '' );
		$query_string = (string) ( $context['query_string'] ?? '' );

		return match ( $field ) {
			'path'         => $path,
			'query_string' => $query_string,
			'user_agent'   => (string) ( $context['user_agent'] ?? '' ),
			default        => '' !== $query_string ? $path . '?' . $query_string : $path,
		};
	}
}
