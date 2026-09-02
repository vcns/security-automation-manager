<?php
/**
 * Detects suspicious HTML/markup injection in the request path and query
 * string (.roadmap/phase3_early_plan.md §11.4).
 *
 * Every rule requires actual tag-open syntax (`<script`, `<svg` + `onload=`,
 * a `javascript:` URI scheme, and similar) rather than a bare "<" or a
 * dangerous-sounding word alone -- a query string legitimately containing
 * "<" (a price comparison, a maths question, a code snippet pasted into a
 * search box) must not match. Per §11.4's explicit guidance ("this detector
 * must be treated carefully because legitimate application requests may
 * submit HTML... default posture should therefore be observation unless the
 * protected endpoint is known not to accept HTML"), this is enforce-capable
 * but still defaults to observation only -- see allowed_control_actions().
 */

declare( strict_types=1 );

namespace WP_SAM\Intelligence\Detectors;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Html_Injection_Detector extends Pattern_Detector {

	public function id(): string {
		return 'html-injection';
	}

	public function family(): string {
		return 'html-injection';
	}

	public function applicable_surfaces(): array {
		return array();
	}

	public function allowed_control_actions(): array {
		return array( 'observe', 'enforce' );
	}

	protected function subject( array $context ): string {
		$path         = (string) ( $context['path'] ?? '' );
		$query_string = (string) ( $context['query_string'] ?? '' );

		return '' !== $query_string ? $path . '?' . $query_string : $path;
	}

	protected function rules(): array {
		return array(
			array(
				'id'          => 'HTMLI-001',
				'pattern'     => '#<script[\s/>]#i',
				'severity'    => 'critical',
				'confidence'  => 0.9,
				'description' => 'Script tag opening.',
			),
			array(
				'id'          => 'HTMLI-002',
				'pattern'     => '#<svg\b[^>]*\bonload\s*=#i',
				'severity'    => 'critical',
				'confidence'  => 0.9,
				'description' => 'SVG tag with an onload handler.',
			),
			array(
				'id'          => 'HTMLI-003',
				'pattern'     => '#<img\b[^>]*\bonerror\s*=#i',
				'severity'    => 'critical',
				'confidence'  => 0.9,
				'description' => 'img tag with an onerror handler.',
			),
			array(
				'id'          => 'HTMLI-004',
				'pattern'     => '#<iframe[\s/>]#i',
				'severity'    => 'high',
				'confidence'  => 0.8,
				'description' => 'Iframe tag opening.',
			),
			array(
				'id'          => 'HTMLI-005',
				'pattern'     => '#<body\b[^>]*\bonload\s*=#i',
				'severity'    => 'high',
				'confidence'  => 0.8,
				'description' => 'body tag with an onload handler.',
			),
			array(
				'id'          => 'HTMLI-006',
				'pattern'     => '#\bjavascript\s*:#i',
				'severity'    => 'high',
				'confidence'  => 0.75,
				'description' => 'javascript: URI scheme.',
			),
			array(
				'id'          => 'HTMLI-007',
				'pattern'     => '#<style[\s/>][^<]*\bexpression\s*\(#i',
				'severity'    => 'medium',
				'confidence'  => 0.6,
				'description' => 'Legacy CSS expression() injection via a style tag.',
			),
			array(
				'id'          => 'HTMLI-008',
				'pattern'     => '#<[a-z][a-z0-9]*\b[^>]*\bon(?:error|load|mouseover|focus|click)\s*=#i',
				'severity'    => 'high',
				'confidence'  => 0.75,
				'description' => 'HTML tag carrying a common XSS event-handler attribute.',
			),
		);
	}
}
