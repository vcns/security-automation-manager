<?php
/**
 * Session/cookie behaviour (Phase 4C, .roadmap/phase3_early_plan.md §10's
 * "session/cookie behaviour" signal), first increment.
 *
 * WordPress core itself -- not this plugin -- sets a `wordpress_test_cookie`
 * whenever it renders the login form, and wp-login.php's own submission
 * handler already checks for it before accepting credentials. A real
 * browser that loaded the login form and is now submitting it always
 * resends that cookie; a script posting straight to wp-login.php with a
 * guessed username/password (skipping the page load entirely) never has
 * it. This deliberately introduces no new cookie of its own -- see
 * Request_Observer::build_context()'s own note on why a broader,
 * site-wide first-party tracking cookie is a bigger product/privacy
 * decision, carried forward rather than built silently here.
 *
 * Only evaluates POST requests on the login surface -- a GET (loading the
 * form itself) never carries the cookie yet by definition and isn't a
 * credential-submission attempt.
 */

declare( strict_types=1 );

namespace WP_SAM\Intelligence\Detectors;

use WP_SAM\Intelligence\Detector;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Login_Cookie_Consistency_Detector extends Detector {

	public function id(): string {
		return 'login-cookie-consistency';
	}

	public function family(): string {
		return 'login-cookie-consistency';
	}

	public function applicable_surfaces(): array {
		return array( 'login' );
	}

	public function evaluate( array $context ): ?array {
		if ( 'POST' !== strtoupper( (string) ( $context['method'] ?? '' ) ) ) {
			return null;
		}

		if ( ! empty( $context['has_login_test_cookie'] ) ) {
			return null;
		}

		return array(
			'severity'   => 'medium',
			'confidence' => 0.7,
			'detail'     => array(
				'session_signal' => 'missing_login_test_cookie',
				'description'    => 'Login POST arrived without the wordpress_test_cookie WordPress itself sets when rendering the login form -- consistent with a scripted credential-stuffing attempt posting directly to wp-login.php rather than a real browser that loaded the form first.',
			),
		);
	}
}
