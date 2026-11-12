<?php
/**
 * Detects common SQL-injection patterns in the request path and query
 * string (.roadmap/phase3_early_plan.md §11.3).
 *
 * Distinguishes structural injection (tautologies, stacked queries,
 * time-based blind techniques -- essentially never occur in natural
 * language or legitimate query strings) from a bare keyword match: UNION
 * SELECT alone is common enough in ordinary free-text search ("union select
 * committee") that it is deliberately scored medium/low-confidence rather
 * than high/critical, per the roadmap's own explicit ask to tell these
 * apart rather than treat every keyword hit the same.
 */

declare( strict_types=1 );

namespace WP_SAM\Intelligence\Detectors;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Sql_Injection_Detector extends Pattern_Detector {

	/**
	 * Returns the stable id of the SQL injection detector.
	 *
	 * @return string Detector id.
	 */
	public function id(): string {
		return 'sql-injection';
	}

	/**
	 * Returns the family the SQL injection detector belongs to.
	 *
	 * @return string Family label.
	 */
	public function family(): string {
		return 'sql-injection';
	}

	/**
	 * Returns the plain-language description of the SQL injection detector shown in the Detectors tab.
	 *
	 * @return string Translated description.
	 */
	public function description(): string {
		return __( 'Flags SQL tautologies, stacked queries, and time-based blind-injection syntax (SLEEP/BENCHMARK) in a request.', 'vcns-security-automation-manager' );
	}

	/**
	 * Returns the surfaces the SQL injection detector runs on.
	 *
	 * @return array Surface slugs, or an empty array for every surface.
	 */
	public function applicable_surfaces(): array {
		return array();
	}

	/**
	 * Returns the request data (path, query string) that the SQL injection rules are matched against.
	 *
	 * @param array $context Request context built by Request_Observer.
	 * @return string Text to match.
	 */
	protected function subject( array $context ): string {
		$path         = (string) ( $context['path'] ?? '' );
		$query_string = (string) ( $context['query_string'] ?? '' );

		return '' !== $query_string ? $path . '?' . $query_string : $path;
	}

	/**
	 * Returns the SQL injection detection rules.
	 *
	 * @return array Rules, each with an id, pattern, severity and description.
	 */
	protected function rules(): array {
		return array(
			array(
				'id'          => 'SQLI-001',
				'pattern'     => '#\bor\s+1\s*=\s*1\b#i',
				'severity'    => 'critical',
				'confidence'  => 0.9,
				'description' => 'Classic numeric tautology (OR 1=1).',
			),
			array(
				'id'          => 'SQLI-002',
				'pattern'     => '#\'\s*or\s*\'1\'\s*=\s*\'1#i',
				'severity'    => 'critical',
				'confidence'  => 0.9,
				'description' => 'Classic string tautology (\' OR \'1\'=\'1).',
			),
			array(
				'id'          => 'SQLI-003',
				'pattern'     => '#\bunion\b(?:\s+\w+){0,3}\s+\bselect\b#i',
				'severity'    => 'medium',
				'confidence'  => 0.5,
				'description' => 'UNION SELECT keyword sequence -- low-confidence, matches legitimate free-text search too.',
			),
			array(
				'id'          => 'SQLI-004',
				'pattern'     => '~\'\s*(?:--|#)~',
				'severity'    => 'high',
				'confidence'  => 0.8,
				'description' => 'Quote followed by a SQL comment marker.',
			),
			array(
				'id'          => 'SQLI-005',
				'pattern'     => '#;\s*(?:drop|delete|insert|update)\s+\w+#i',
				'severity'    => 'critical',
				'confidence'  => 0.9,
				'description' => 'Stacked query attempting a destructive statement.',
			),
			array(
				'id'          => 'SQLI-006',
				'pattern'     => '#\bsleep\s*\(\s*\d+\s*\)#i',
				'severity'    => 'high',
				'confidence'  => 0.85,
				'description' => 'Time-based blind SQLi via SLEEP().',
			),
			array(
				'id'          => 'SQLI-007',
				'pattern'     => '#\bbenchmark\s*\(#i',
				'severity'    => 'high',
				'confidence'  => 0.8,
				'description' => 'Time-based blind SQLi via BENCHMARK().',
			),
		);
	}
}
