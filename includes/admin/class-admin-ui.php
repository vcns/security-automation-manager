<?php
/**
 * WordPress Admin UI: menus, settings API, AJAX handlers.
 *
 * Registers a top-level "Security Automation Manager" menu with these pages:
 *   1. security-automation-manager             – Overview: per-pillar status summary
 *   2. security-automation-manager-dashboard   – CSP: surface profiles, source inventory,
 *      violations, scan history, and settings (promotion gates, learning window, cron schedule,
 *      notify email), all as tabs on one page
 *   3. security-automation-manager-policy-audit – policy history, decisions, provenance
 *   4. security-automation-manager-readiness    – plugin-specific health checks and reset
 *
 * All form submissions are protected by check_admin_referer() and
 * current_user_can('manage_options').
 */

declare( strict_types=1 );

namespace WP_SAM\Admin;

use WP_SAM\Plugin;
use WP_SAM\CSP\Automation_Config;
use WP_SAM\CSP\Policy_Builder;
use WP_SAM\CSP\Policy_Change_Manager;
use WP_SAM\CSP\Policy_Version_Manager;
use WP_SAM\CSP\Scheduler;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class Admin_UI {

	private Plugin $plugin;

	public function __construct( Plugin $plugin ) {
		$this->plugin = $plugin;
	}

	// ── Bootstrap ─────────────────────────────────────────────────────────────

	public function register(): void {
		add_action( 'admin_menu', array( $this, 'add_menu_pages' ) );
		add_action( 'admin_init', array( $this, 'register_settings' ) );
		add_action( 'admin_enqueue_scripts', array( $this, 'enqueue_assets' ) );
		add_action( 'admin_notices', array( $this, 'display_admin_notices' ) );
		add_filter( 'plugin_action_links_' . plugin_basename( WP_SAM_FILE ), array( $this, 'add_plugin_action_links' ) );
		add_filter( 'plugin_row_meta', array( $this, 'add_plugin_row_meta' ), 10, 2 );
		add_filter( 'admin_footer_text', array( $this, 'filter_admin_footer_text' ) );

		// AJAX handlers.
		add_action( 'admin_post_wp_sam_reset_data', array( $this, 'handle_reset_data' ) );
		add_action( 'wp_ajax_wp_sam_manual_scan', array( $this, 'ajax_manual_scan' ) );
		add_action( 'wp_ajax_wp_sam_approve_source', array( $this, 'ajax_approve_source' ) );
		add_action( 'wp_ajax_wp_sam_deny_source', array( $this, 'ajax_deny_source' ) );
		add_action( 'wp_ajax_wp_sam_revert_source', array( $this, 'ajax_revert_source' ) );
		add_action( 'wp_ajax_wp_sam_undo_source_decision', array( $this, 'ajax_undo_source_decision' ) );
		add_action( 'wp_ajax_wp_sam_toggle_mode', array( $this, 'ajax_toggle_mode' ) );
		add_action( 'wp_ajax_wp_sam_set_automation_mode', array( $this, 'ajax_set_automation_mode' ) );
	}

	// ── Menu registration ─────────────────────────────────────────────────────

	public function add_menu_pages(): void {
		add_menu_page(
			__( 'Security Automation Manager', 'security-automation-manager' ),
			__( 'Security Automation Manager', 'security-automation-manager' ),
			'manage_options',
			'security-automation-manager',
			array( $this, 'render_overview' ),
			'dashicons-shield',
			80
		);

		add_submenu_page(
			'security-automation-manager',
			__( 'Overview', 'security-automation-manager' ),
			__( 'Overview', 'security-automation-manager' ),
			'manage_options',
			'security-automation-manager',
			array( $this, 'render_overview' )
		);

		add_submenu_page(
			'security-automation-manager',
			__( 'CSP', 'security-automation-manager' ),
			__( 'CSP', 'security-automation-manager' ),
			'manage_options',
			'security-automation-manager-dashboard',
			array( $this, 'render_dashboard' )
		);

		add_submenu_page(
			'security-automation-manager',
			__( 'Policy Audit', 'security-automation-manager' ),
			__( 'Policy Audit', 'security-automation-manager' ),
			'manage_options',
			'security-automation-manager-policy-audit',
			array( $this, 'render_policy_audit' )
		);

		add_submenu_page(
			'security-automation-manager',
			__( 'Readiness', 'security-automation-manager' ),
			__( 'Readiness', 'security-automation-manager' ),
			'manage_options',
			'security-automation-manager-readiness',
			array( $this, 'render_readiness' )
		);
	}

	// ── Settings API ──────────────────────────────────────────────────────────

	public function register_settings(): void {
		$settings = array(
			'wp_sam_cron_hour'                     => 'absint',
			'wp_sam_notify_email'                  => 'sanitize_email',
			'wp_sam_enforce_gate_violation_window' => 'absint',
			'wp_sam_learning_window_hours'         => 'absint',
			'wp_sam_report_endpoint_url'           => array( $this, 'sanitize_report_endpoint_url' ),
			'wp_sam_reporting_transport'           => array( $this, 'sanitize_reporting_transport' ),
			'wp_sam_policy_header_name'            => array( $this, 'sanitize_policy_header_name' ),
			'wp_sam_automation_config'             => array( $this, 'sanitize_automation_config' ),
			// Data retention: days to keep violation reports (0 = keep forever).
			'wp_sam_violation_retention_days'      => 'absint',
		);

		foreach ( $settings as $option => $callback ) {
			register_setting( 'wp_sam_settings_group', $option, array( 'sanitize_callback' => $callback ) );
		}
	}

	public function add_plugin_action_links( array $links ): array {
		$settings_link = sprintf(
			'<a href="%1$s">%2$s</a>',
			esc_url( admin_url( 'admin.php?page=security-automation-manager-dashboard&tab=settings' ) ),
			esc_html__( 'Settings', 'security-automation-manager' )
		);

		$reset_link = sprintf(
			'<a href="%1$s">%2$s</a>',
			esc_url( admin_url( 'admin.php?page=security-automation-manager-readiness#wp-sam-reset' ) ),
			esc_html__( 'Reset', 'security-automation-manager' )
		);

		return array(
			'settings' => $settings_link,
			'reset'    => $reset_link,
		) + $links;
	}

	public function add_plugin_row_meta( array $links, string $file ): array {
		if ( plugin_basename( WP_SAM_FILE ) !== $file ) {
			return $links;
		}

		$update_posture = 'github' === WP_SAM_DISTRIBUTION_CHANNEL
			? __( 'Updates: GitHub Releases channel with checksum verification.', 'security-automation-manager' )
			: __( 'Updates: WordPress.org package; no custom updater runs in this build.', 'security-automation-manager' );

		$links[] = sprintf(
			'<span class="wp-sam-update-posture">%s</span>',
			esc_html( $update_posture )
		);

		return $links;
	}

	/**
	 * Suppresses the default "Thank you for creating with WordPress." footer
	 * text on this plugin's own admin pages only; every other admin screen is
	 * left untouched.
	 */
	public function filter_admin_footer_text( string $text ): string {
		$screen = function_exists( 'get_current_screen' ) ? get_current_screen() : null;
		if ( $screen && in_array( $screen->id, $this->plugin_page_hooks(), true ) ) {
			return '';
		}

		return $text;
	}

	public function sanitize_report_endpoint_url( mixed $url ): string {
		$url = trim( (string) $url );
		if ( '' === $url ) {
			return '';
		}

		if ( preg_match( '/[\r\n"\\\\]/', $url ) ) {
			return '';
		}

		$url   = esc_url_raw( $url );
		$parts = wp_parse_url( $url );
		if ( ! is_array( $parts ) ) {
			return '';
		}

		$scheme = strtolower( (string) ( $parts['scheme'] ?? '' ) );
		$host   = (string) ( $parts['host'] ?? '' );
		if ( '' === $host || ! in_array( $scheme, array( 'http', 'https' ), true ) ) {
			return '';
		}

		return $url;
	}

	public function sanitize_policy_header_name( mixed $header_name ): string {
		return Policy_Builder::sanitize_custom_policy_header_name( $header_name );
	}

	// ── Asset enqueue ─────────────────────────────────────────────────────────

	public function sanitize_reporting_transport( mixed $transport ): string {
		return Policy_Builder::sanitize_reporting_transport( $transport );
	}

	public function sanitize_automation_config( mixed $config ): array {
		return ( new Automation_Config() )->normalise_admin_input( is_array( $config ) ? $config : array() );
	}

	/**
	 * Admin-page hook suffixes this plugin registers, shared by enqueue_assets()
	 * and filter_admin_footer_text() so the list only lives in one place.
	 *
	 * WordPress derives a submenu's hook suffix from sanitize_title() of the
	 * top-level menu's title text, not its slug -- since the top-level menu
	 * title is "Security Automation Manager", every submenu hook is prefixed
	 * "security-automation-manager_page_".
	 */
	private function plugin_page_hooks(): array {
		return array(
			'toplevel_page_security-automation-manager',
			'security-automation-manager_page_security-automation-manager-dashboard',
			'security-automation-manager_page_security-automation-manager-policy-audit',
			'security-automation-manager_page_security-automation-manager-readiness',
		);
	}

	public function enqueue_assets( string $hook_suffix ): void {
		if ( ! in_array( $hook_suffix, $this->plugin_page_hooks(), true ) ) {
			return;
		}

		wp_enqueue_style(
			'wp-sam-admin',
			WP_SAM_URL . 'assets/css/admin.css',
			array(),
			WP_SAM_VERSION
		);

		wp_enqueue_script(
			'wp-sam-admin',
			WP_SAM_URL . 'assets/js/admin.js',
			array( 'jquery' ),
			WP_SAM_VERSION,
			true
		);

		wp_localize_script(
			'wp-sam-admin',
			'wpSamAdmin',
			array(
				'ajaxUrl'   => admin_url( 'admin-ajax.php' ),
				'restUrl'   => esc_url_raw( rest_url( 'security-manager/v1/admin/' ) ),
				'nonce'     => wp_create_nonce( 'wp_sam_admin_nonce' ),
				'restNonce' => wp_create_nonce( 'wp_rest' ),
				'i18n'      => array(
					'scanning'       => __( 'Scanning…', 'security-automation-manager' ),
					'scanDone'       => __( 'Scan complete.', 'security-automation-manager' ),
					'scanError'      => __( 'Scan failed. Check error log.', 'security-automation-manager' ),
					'reasonRequired' => __( 'A decision reason is required.', 'security-automation-manager' ),
				),
			)
		);
	}

	// ── Page renderers ────────────────────────────────────────────────────────

	public function render_overview(): void {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'You do not have permission to view this page.', 'security-automation-manager' ) );
		}
		require WP_SAM_DIR . 'includes/admin/views/page-overview.php';
	}

	public function render_dashboard(): void {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'You do not have permission to view this page.', 'security-automation-manager' ) );
		}
		require WP_SAM_DIR . 'includes/admin/views/page-csp-dashboard.php';
	}

	public function render_policy_audit(): void {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'You do not have permission to view this page.', 'security-automation-manager' ) );
		}
		require WP_SAM_DIR . 'includes/admin/views/page-policy-audit.php';
	}

	public function render_readiness(): void {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'You do not have permission to view this page.', 'security-automation-manager' ) );
		}

		$readiness = ( new Readiness_Checker() )->get_report();
		require WP_SAM_DIR . 'includes/admin/views/page-readiness.php';
	}

	public function handle_reset_data(): void {
		check_admin_referer( 'wp_sam_reset_data' );
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'You do not have permission to reset plugin data.', 'security-automation-manager' ) );
		}

		$password     = (string) wp_unslash( $_POST['wp_sam_current_password'] ?? '' );
		$confirmation = sanitize_text_field( wp_unslash( $_POST['wp_sam_reset_confirmation'] ?? '' ) );

		if ( 'RESET CSP DATA' !== $confirmation || ! $this->current_user_password_is_valid( $password ) ) {
			$this->redirect_to_readiness( 'failed' );
		}

		$result = ( new Data_Resetter() )->reset();

		$this->redirect_to_readiness(
			empty( $result['tables_failed'] ) ? 'success' : 'partial'
		);
	}

	private function current_user_password_is_valid( string $password ): bool {
		if ( '' === $password || ! function_exists( 'wp_get_current_user' ) || ! function_exists( 'wp_check_password' ) ) {
			return false;
		}

		$user = wp_get_current_user();
		if ( ! is_object( $user ) || empty( $user->ID ) || empty( $user->user_pass ) ) {
			return false;
		}

		return wp_check_password( $password, (string) $user->user_pass, (int) $user->ID );
	}

	private function redirect_to_readiness( string $result ): void {
		$url = add_query_arg(
			array( 'wp_sam_reset' => $result ),
			admin_url( 'admin.php?page=security-automation-manager-readiness#wp-sam-reset' )
		);

		wp_safe_redirect( $url );
		exit;
	}

	// ── Admin notices ─────────────────────────────────────────────────────────

	public function display_admin_notices(): void {
		// Platform constraint warning (R9): wp-admin strict CSP is best-effort because
		// WordPress core Trac #59446 is unresolved. Only show when the admin surface
		// profile is in enforce mode, and only once per session per user.
		$this->maybe_show_admin_csp_warning();

		$notices = get_option( 'wp_sam_admin_notices', array() );
		if ( ! is_array( $notices ) || empty( $notices ) ) {
			return;
		}
		foreach ( $notices as $notice ) {
			$type = 'error' === $notice['severity'] ? 'error' : 'warning';
			printf(
				'<div class="notice notice-%1$s is-dismissible"><p><strong>%2$s</strong> [%3$s] %4$s</p></div>',
				esc_attr( $type ),
				esc_html__( 'CSP Automation Manager:', 'security-automation-manager' ),
				esc_html( $notice['component'] . '/' . $notice['event'] ),
				esc_html( $notice['detail'] )
			);
		}
		delete_option( 'wp_sam_admin_notices' );
	}

	/**
	 * Shows a one-per-session notice when the admin surface CSP is in enforce mode.
	 * WordPress core Trac #59446 means some admin UI components may break under
	 * strict nonce-based CSP. This warns the admin to monitor violations first.
	 */
	private function maybe_show_admin_csp_warning(): void {
		$user_id  = get_current_user_id();
		$transkey = 'wp_sam_admin59446_warned_' . $user_id;
		if ( get_transient( $transkey ) ) {
			return;
		}

		global $wpdb;
		$table = $wpdb->prefix . 'csp_policy_profiles';
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery,WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		$mode = $wpdb->get_var( $wpdb->prepare( "SELECT mode FROM {$table} WHERE surface = %s LIMIT 1", 'admin' ) );

		if ( 'enforce' !== $mode ) {
			return;
		}

		set_transient( $transkey, 1, DAY_IN_SECONDS );
		printf(
			'<div class="notice notice-info is-dismissible"><p>%s</p></div>',
			wp_kses(
				sprintf(
					/* translators: %s: URL to WordPress core Trac ticket */
					__( '<strong>CSP Automation Manager:</strong> The wp-admin CSP surface is in <strong>enforce mode</strong>. WordPress core <a href="%s" target="_blank" rel="noopener">Trac #59446</a> is unresolved - some admin UI components may be blocked. Monitor violation reports before keeping enforce mode active.', 'security-automation-manager' ),
					'https://core.trac.wordpress.org/ticket/59446'
				),
				array(
					'strong' => array(),
					'a'      => array(
						'href'   => array(),
						'target' => array(),
						'rel'    => array(),
					),
				)
			)
		);
	}

	// ── AJAX: manual scan ─────────────────────────────────────────────────────

	public function ajax_manual_scan(): void {
		check_ajax_referer( 'wp_sam_admin_nonce', 'nonce' );
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( array( 'message' => __( 'Insufficient permissions.', 'security-automation-manager' ) ), 403 );
		}

		$scheduler = new Scheduler( $this->plugin->audit );
		$results   = $scheduler->run_manual_scan();

		if ( isset( $results['error'] ) ) {
			wp_send_json_error( array( 'message' => $results['error'] ) );
		} else {
			wp_send_json_success( $results );
		}
	}

	// ── AJAX: approve/deny source ─────────────────────────────────────────────

	public function ajax_approve_source(): void {
		check_ajax_referer( 'wp_sam_admin_nonce', 'nonce' );
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( null, 403 );
		}
		$this->decide_source( (int) ( $_POST['source_id'] ?? 0 ), 'approved' );
	}

	public function ajax_deny_source(): void {
		check_ajax_referer( 'wp_sam_admin_nonce', 'nonce' );
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( null, 403 );
		}
		$this->decide_source( (int) ( $_POST['source_id'] ?? 0 ), 'rejected' );
	}

	public function ajax_revert_source(): void {
		check_ajax_referer( 'wp_sam_admin_nonce', 'nonce' );
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( null, 403 );
		}
		$this->decide_source( (int) ( $_POST['source_id'] ?? 0 ), 'reverted' );
	}

	public function ajax_undo_source_decision(): void {
		check_ajax_referer( 'wp_sam_admin_nonce', 'nonce' );
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( null, 403 );
		}
		$this->decide_source( (int) ( $_POST['source_id'] ?? 0 ), 'undone' );
	}

	private function decide_source( int $id, string $action ): void {
		if ( $id <= 0 ) {
			wp_send_json_error( array( 'message' => __( 'Invalid source ID.', 'security-automation-manager' ) ) );
		}

		$reason = sanitize_text_field( wp_unslash( $_POST['reason'] ?? '' ) );
		if ( '' === trim( $reason ) ) {
			wp_send_json_error( array( 'message' => __( 'A decision reason is required.', 'security-automation-manager' ) ) );
		}

		$manager = new Policy_Change_Manager( $this->plugin->audit, null, new Policy_Version_Manager( $this->plugin->policy_builder ) );
		if ( 'approved' === $action ) {
			$ok = $manager->approve_source( $id, $reason );
		} elseif ( 'reverted' === $action ) {
			$ok = $manager->revert_source( $id, $reason );
		} elseif ( 'undone' === $action ) {
			$ok = $manager->undo_source_decision( $id, $reason );
		} else {
			$ok = $manager->reject_source( $id, $reason );
		}

		if ( ! $ok ) {
			wp_send_json_error( array( 'message' => __( 'Could not record policy decision.', 'security-automation-manager' ) ) );
		}
		wp_send_json_success();
	}

	// ── AJAX: toggle surface mode ─────────────────────────────────────────────

	public function ajax_toggle_mode(): void {
		check_ajax_referer( 'wp_sam_admin_nonce', 'nonce' );
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( null, 403 );
		}

		$surface = sanitize_text_field( wp_unslash( $_POST['surface'] ?? '' ) );
		$mode    = sanitize_text_field( wp_unslash( $_POST['mode'] ?? '' ) );

		if ( ! in_array( $surface, array( 'frontend', 'admin', 'login', 'api' ), true ) ) {
			wp_send_json_error( array( 'message' => 'Invalid surface.' ) );
		}
		if ( ! in_array( $mode, array( 'report-only', 'enforce', 'disabled' ), true ) ) {
			wp_send_json_error( array( 'message' => 'Invalid mode.' ) );
		}

		// Full promotion gate: enforce requires passing all configured checks.
		if ( 'enforce' === $mode ) {
			$gate_result = $this->gate_allows_enforce( $surface );
			if ( true !== $gate_result ) {
				wp_send_json_error( array( 'message' => $gate_result ) );
			}
		}

		global $wpdb;
		$wpdb->update(
			$wpdb->prefix . 'csp_policy_profiles',
			array(
				'mode'       => $mode,
				'updated_at' => current_time( 'mysql', true ),
			),
			array( 'surface' => $surface ),
			array( '%s', '%s' ),
			array( '%s' )
		);
		wp_send_json_success();
	}

	public function ajax_set_automation_mode(): void {
		check_ajax_referer( 'wp_sam_admin_nonce', 'nonce' );
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( null, 403 );
		}

		$surface = sanitize_text_field( wp_unslash( $_POST['surface'] ?? '' ) );
		$mode    = sanitize_text_field( wp_unslash( $_POST['mode'] ?? '' ) );

		if ( ! in_array( $surface, Automation_Config::SURFACES, true ) ) {
			wp_send_json_error( array( 'message' => __( 'Invalid surface.', 'security-automation-manager' ) ) );
		}

		if ( ! in_array( $mode, Automation_Config::MODES, true ) ) {
			wp_send_json_error( array( 'message' => __( 'Invalid automation mode.', 'security-automation-manager' ) ) );
		}

		( new Automation_Config() )->update_surface_mode( $surface, $mode );

		wp_send_json_success(
			array(
				'mode'  => $mode,
				'label' => Automation_Config::mode_label( $mode ),
			)
		);
	}

	// ── Promotion gate ────────────────────────────────────────────────────────

	/**
	 * Checks all configured gates before allowing enforce mode promotion.
	 *
	 * Implements §4.12:
	 *   Gate 1 -- At least one approved source or hash must exist for the surface.
	 *   Gate 2 -- No violations recorded within the configured time window.
	 *   Gate 3 -- No active temporary override that has not yet expired.
	 *
	 * @param  string       $surface  CSP surface identifier.
	 * @return true|string  true if all gates pass; a human-readable failure reason string otherwise.
	 */
	private function gate_allows_enforce( string $surface ): bool|string {
		global $wpdb;

		// ── Gate 1: approved source or hash inventory ─────────────────────────
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery,WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		$src_count = (int) $wpdb->get_var(
			$wpdb->prepare(
				"SELECT COUNT(*) FROM {$wpdb->prefix}csp_source_inventory WHERE surface = %s AND approval_state = 'approved'",
				$surface
			)
		);
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery,WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		$hash_count = (int) $wpdb->get_var(
			$wpdb->prepare(
				"SELECT COUNT(*) FROM {$wpdb->prefix}csp_hash_inventory WHERE surface = %s AND status = 'active'",
				$surface
			)
		);

		if ( ( $src_count + $hash_count ) === 0 ) {
			return __( 'Cannot promote to enforce: no approved sources or hashes found for this surface. Run a scan and approve at least one source first.', 'security-automation-manager' );
		}

		// ── Gate 2: no violations within the configured time window ───────────
		$window_hours = max( 1, (int) get_option( 'wp_sam_enforce_gate_violation_window', 24 ) );
		$since        = gmdate( 'Y-m-d H:i:s', time() - ( $window_hours * HOUR_IN_SECONDS ) );

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery,WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		$recent_violations = (int) $wpdb->get_var(
			$wpdb->prepare(
				"SELECT COUNT(*) FROM {$wpdb->prefix}csp_violation_reports
				WHERE profile_surface = %s
				AND reported_at >= %s",
				$surface,
				$since
			)
		);

		if ( $recent_violations > 0 ) {
			return sprintf(
				/* translators: 1: violation count, 2: hours */
				__( 'Cannot promote to enforce: %1$d violation(s) recorded for this surface in the last %2$d hour(s). Resolve violations in report-only mode first, or extend the violation window in Settings.', 'security-automation-manager' ),
				$recent_violations,
				$window_hours
			);
		}

		// ── Gate 3: no active unresolved temporary override ───────────────────
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery,WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		$profile = $wpdb->get_row(
			$wpdb->prepare(
				"SELECT override_expires_at, override_owner FROM {$wpdb->prefix}csp_policy_profiles WHERE surface = %s LIMIT 1",
				$surface
			),
			ARRAY_A
		);

		if ( $profile ) {
			$expires_at = $profile['override_expires_at'] ?? null;
			$owner      = $profile['override_owner'] ?? null;

			if ( ! empty( $expires_at ) && ! empty( $owner ) ) {
				$expires_ts = strtotime( $expires_at );
				if ( false !== $expires_ts && $expires_ts > time() ) {
					return sprintf(
						/* translators: 1: override owner, 2: expiry datetime */
						__( 'Cannot promote to enforce: a temporary override set by "%1$s" is active until %2$s. Wait for it to expire or remove it before enabling enforce mode.', 'security-automation-manager' ),
						esc_html( $owner ),
						esc_html( $expires_at )
					);
				}
			}
		}

		return true;
	}
}
