<?php
/**
 * Recognises requests to legacy or commonly-abused WordPress endpoints
 * (.roadmap/phase3_early_plan.md §11.13).
 *
 * xmlrpc.php is the flagship signal here, and deliberately scored low/
 * medium rather than high/critical: it's still a legitimate, actively-used
 * core endpoint (the mobile app, pingback, some plugins), and this family
 * can only see the request path, not the XML-RPC method actually being
 * called (pingback.ping SSRF abuse and system.multicall credential-
 * stuffing both use the same URL with different POST bodies, which this
 * detector -- like every other Pattern_Detector -- never inspects). Per
 * the roadmap's own explicit wording ("RPC/XML-RPC controls must be
 * configurable rather than assumed universally safe to block"), this is
 * enforce-capable but still defaults to observation: whether xmlrpc.php
 * is even in genuine use is a per-site judgement call, not something this
 * detector can determine for every install.
 */

declare( strict_types=1 );

namespace WP_SAM\Intelligence\Detectors;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Legacy_Endpoint_Detector extends Pattern_Detector {

	public function id(): string {
		return 'legacy-endpoints';
	}

	public function family(): string {
		return 'legacy-endpoints';
	}

	public function applicable_surfaces(): array {
		return array();
	}

	public function allowed_control_actions(): array {
		return array( 'observe', 'enforce' );
	}

	protected function subject( array $context ): string {
		return (string) ( $context['path'] ?? '' );
	}

	protected function rules(): array {
		return array(
			array(
				'id'          => 'LEGACY-001',
				'pattern'     => '#(?:^|/)xmlrpc\.php$#i',
				'severity'    => 'medium',
				'confidence'  => 0.55,
				'description' => 'XML-RPC endpoint -- still legitimate in some setups (pingback, the mobile app, some plugins), but also a common pingback-SSRF and system.multicall credential-stuffing target.',
			),
			array(
				'id'          => 'LEGACY-002',
				'pattern'     => '#(?:^|/)wp-trackback\.php$#i',
				'severity'    => 'medium',
				'confidence'  => 0.6,
				'description' => 'Trackback endpoint -- a long-standing spam and abuse vector, rarely used legitimately today.',
			),
			array(
				'id'          => 'LEGACY-003',
				'pattern'     => '#(?:^|/)wp-app\.php$#i',
				'severity'    => 'low',
				'confidence'  => 0.7,
				'description' => 'Atom Publishing Protocol endpoint, removed from WordPress core since 3.5 -- a hit almost certainly means a stale scanner signature, not a real endpoint.',
			),
		);
	}
}
