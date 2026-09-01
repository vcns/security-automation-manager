<?php
/**
 * Detects common shell command-injection attempts in the request path and
 * query string (.roadmap/phase3_early_plan.md §11.2).
 *
 * Every command-word rule carries a `(?!\s*=)` negative lookahead: without
 * it, an ordinary WordPress query var that happens to share a name with a
 * shell utility (`?cat=5`, `?id=5` are both real, common WP query-var names)
 * would match a bare `;cat`/`;id` fragment inside a longer query string.
 * Requiring that the matched word is NOT immediately followed by `=` keeps
 * the rule scoped to actual shell syntax, which never takes that form.
 */

declare( strict_types=1 );

namespace WP_SAM\Intelligence\Detectors;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Command_Injection_Detector extends Pattern_Detector {

	public function id(): string {
		return 'command-injection';
	}

	public function family(): string {
		return 'command-injection';
	}

	public function applicable_surfaces(): array {
		return array();
	}

	protected function subject( array $context ): string {
		$path         = (string) ( $context['path'] ?? '' );
		$query_string = (string) ( $context['query_string'] ?? '' );

		return '' !== $query_string ? $path . '?' . $query_string : $path;
	}

	protected function rules(): array {
		return array(
			array(
				'id'          => 'CMDI-001',
				'pattern'     => '#;\s*(?:cat|ls|wget|curl|nc|bash|sh|whoami|id|uname|ping)\b(?!\s*=)#i',
				'severity'    => 'high',
				'confidence'  => 0.75,
				'description' => 'Shell command chained after a semicolon.',
			),
			array(
				'id'          => 'CMDI-002',
				'pattern'     => '#`[^`]+`#',
				'severity'    => 'high',
				'confidence'  => 0.8,
				'description' => 'Backtick command substitution.',
			),
			array(
				'id'          => 'CMDI-003',
				'pattern'     => '#\$\([^)]+\)#',
				'severity'    => 'high',
				'confidence'  => 0.8,
				'description' => '$() command substitution.',
			),
			array(
				'id'          => 'CMDI-004',
				'pattern'     => '#\|\s*(?:cat|nc|bash|sh)\b(?!\s*=)#i',
				'severity'    => 'high',
				'confidence'  => 0.7,
				'description' => 'Shell command piped to another utility.',
			),
		);
	}
}
