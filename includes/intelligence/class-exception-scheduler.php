<?php
/**
 * Cron wiring for time-bound exceptions (GitHub issue #177): a single daily
 * hook that (a) flips any exception past its expiry_date to 'expired' via
 * Exception_Store::expire_overdue(), and (b) emails whoever's configured to
 * hear about it when an exception is approaching expiry, via
 * Exception_Store::due_for_notice().
 *
 * Self-scheduling (rather than activation-time scheduling), matching
 * Certificates\Renewal_Scheduler, so this heals a cleared cron table and
 * works on sites that updated in place without a deactivate/reactivate
 * cycle.
 */

declare( strict_types=1 );

namespace WP_SAM\Intelligence;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Exception_Scheduler {

	public const CHECK_HOOK = 'wp_sam_exception_check';

	/** Days before expiry an active exception starts appearing in the notice email. */
	public const DEFAULT_NOTICE_WINDOW_DAYS = 7;

	private Exception_Store $store;

	/**
	 * Constructor.
	 *
	 * @param Exception_Store|null $store Exception store, a new one is created when omitted.
	 */
	public function __construct( ?Exception_Store $store = null ) {
		$this->store = null !== $store ? $store : new Exception_Store();
	}

	/**
	 * Registers the daily check and schedules it when it is not scheduled yet.
	 *
	 * @return void
	 */
	public function register(): void {
		add_action( self::CHECK_HOOK, array( $this, 'run_daily_check' ) );

		if ( ! wp_next_scheduled( self::CHECK_HOOK ) ) {
			wp_schedule_event( time() + HOUR_IN_SECONDS, 'daily', self::CHECK_HOOK );
		}
	}

	/**
	 * Expires overdue exceptions and notifies about those expiring soon.
	 *
	 * @return void
	 */
	public function run_daily_check(): void {
		$this->store->expire_overdue();
		$this->maybe_notify_of_upcoming_expiry();
	}

	/**
	 * Emails the notification address about exceptions that are about to expire.
	 *
	 * @return void
	 */
	private function maybe_notify_of_upcoming_expiry(): void {
		$window_days = max( 1, (int) get_option( 'wp_sam_exception_notice_window_days', self::DEFAULT_NOTICE_WINDOW_DAYS ) );
		$due         = $this->store->due_for_notice( $window_days );

		if ( empty( $due ) ) {
			return;
		}

		$email = (string) get_option( 'wp_sam_notify_email', get_option( 'admin_email' ) );
		if ( empty( $email ) || ! is_email( $email ) ) {
			return;
		}

		$subject = sprintf(
			/* translators: 1: site name, 2: number of exceptions expiring soon */
			_n(
				'[%1$s] %2$d exception expiring soon',
				'[%1$s] %2$d exceptions expiring soon',
				count( $due ),
				'vcns-security-automation-manager'
			),
			get_bloginfo( 'name' ),
			count( $due )
		);

		$lines = array();
		foreach ( $due as $exception ) {
			$lines[] = sprintf(
				/* translators: 1: control, 2: surface, 3: expiry date, 4: owner */
				__( '- %1$s (%2$s), expires %3$s, owner: %4$s', 'vcns-security-automation-manager' ),
				$exception['control'],
				'' !== (string) $exception['surface'] ? $exception['surface'] : __( 'all surfaces', 'vcns-security-automation-manager' ),
				$exception['expiry_date'],
				$exception['owner']
			);
		}

		$message = sprintf(
			/* translators: 1: list of expiring exceptions, 2: admin URL */
			__( "The following exceptions are approaching their expiry date:\n\n%1\$s\n\nReview them: %2\$s", 'vcns-security-automation-manager' ),
			implode( "\n", $lines ),
			admin_url( 'admin.php?page=security-automation-manager&tab=exceptions' )
		);

		wp_mail( $email, $subject, $message );
	}
}
