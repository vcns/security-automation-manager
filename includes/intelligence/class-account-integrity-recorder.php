<?php
/**
 * Records the two most cleanly-hookable integrity signals from
 * .roadmap/phase3_early_plan.md §16 (Integrity Monitoring): a new
 * administrator account, and an existing user being granted the
 * administrator role. Both are written through the same Change_Log_Store
 * Change_Attribution_Recorder already uses for plugin/theme/core changes --
 * see Change_Log_Store's own docblock for why that makes both types appear
 * in Change_Timeline_Builder's merged view automatically.
 *
 * §16 lists several other candidate signals (unexpected PHP/executable
 * files, unusual cron entries, unexpected plugin/theme file changes,
 * critical configuration changes). None of those are implemented here --
 * each needs its own filesystem/cron-scanning infrastructure this codebase
 * doesn't have yet, and faking partial coverage would be worse than being
 * explicit about the gap (the same reasoning Security_Health's
 * external_verification row already applies to §20/§21).
 *
 * Hooks only set_user_role -- WordPress core's own new-user registration
 * path (wp_insert_user() -> WP_User::set_role()) fires this exactly once
 * for a brand-new user too, so one hook covers both "new admin account"
 * (old_roles empty) and "existing user promoted to admin" (old_roles
 * non-empty, administrator not among them) without needing user_register
 * as well, which fires before roles are attached and would double-count.
 */

declare( strict_types=1 );

namespace WP_SAM\Intelligence;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Account_Integrity_Recorder {

	private Change_Log_Store $log;

	public function __construct( Change_Log_Store $log ) {
		$this->log = $log;
	}

	public function register(): void {
		add_action( 'set_user_role', array( $this, 'on_set_user_role' ), 10, 3 );
	}

	/** @param array<int, string> $old_roles */
	public function on_set_user_role( int $user_id, string $role, array $old_roles ): void {
		if ( 'administrator' !== $role || in_array( 'administrator', $old_roles, true ) ) {
			return;
		}

		$user       = get_userdata( $user_id );
		$user_login = false !== $user ? (string) $user->user_login : (string) $user_id;

		if ( empty( $old_roles ) ) {
			$this->log->record( 'admin_account_created', $user_login, '', $role );
			return;
		}

		$this->log->record( 'admin_role_granted', $user_login, implode( ',', $old_roles ), $role );
	}
}
