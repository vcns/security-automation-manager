<?php
/**
 * Admin view: Traffic Controls (Phase 3E, .roadmap/phase3_early_plan.md §13).
 * This plugin's first active request-blocking capability -- see
 * Intelligence\Traffic_Guard's docblock for the default-safety design
 * (every surface starts in 'observe' mode; nothing blocks until an
 * administrator explicitly promotes a surface to 'enforce').
 *
 * Tabs: Policy (per-surface mode + thresholds), IP Rules (manual allow/
 * block list), Blocks (live view of automatic progressive-response state,
 * with Release/Make Persistent admin actions), Network Intelligence (its
 * own Tor/ASN/Geo-IP/Well-Known Files/Network Rules sub-tabs), Detectors,
 * and Custom Rules.
 *
 * Rendered by Admin_UI::render_traffic().
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use WP_SAM\Admin\Admin_UI;
use WP_SAM\Intelligence\Ads_Txt_Store;
use WP_SAM\Intelligence\Agents_Rules_Store;
use WP_SAM\Intelligence\App_Ads_Txt_Store;
use WP_SAM\Intelligence\Asn_Lookup_Store;
use WP_SAM\Intelligence\Country_Groups;
use WP_SAM\Intelligence\Custom_Rule_Store;
use WP_SAM\Intelligence\Detector_Policy_Store;
use WP_SAM\Intelligence\Detector_Registry;
use WP_SAM\Intelligence\Detectors\Custom_Rule_Detector;
use WP_SAM\Intelligence\Geo_Ip_Store;
use WP_SAM\Intelligence\Humans_Txt_Store;
use WP_SAM\Intelligence\Ip_Resolver;
use WP_SAM\Intelligence\Ip_Rule_Store;
use WP_SAM\Intelligence\Iso_Countries;
use WP_SAM\Intelligence\Network_Rule_Store;
use WP_SAM\Intelligence\Own_Address_Store;
use WP_SAM\Intelligence\Robots_Rules_Store;
use WP_SAM\Intelligence\Scanner_Identity_Store;
use WP_SAM\Intelligence\Security_Txt_Store;
use WP_SAM\Intelligence\Site_Country;
use WP_SAM\Intelligence\Tor_Exit_List_Store;
use WP_SAM\Intelligence\Traffic_Block_Store;
use WP_SAM\Intelligence\Traffic_Policy_Store;
use WP_SAM\Intelligence\Well_Known_File_Catalog;
use WP_SAM\Intelligence\Well_Known_File_Store;

$base_url     = admin_url( 'admin.php?page=security-automation-manager-traffic' );
$tab          = isset( $_GET['tab'] ) ? sanitize_text_field( wp_unslash( $_GET['tab'] ) ) : 'policy'; // phpcs:ignore WordPress.Security.NonceVerification.Recommended
$allowed_tabs = array( 'policy', 'ip-rules', 'blocks', 'network-intelligence', 'detectors', 'custom-rules' );
if ( ! in_array( $tab, $allowed_tabs, true ) ) {
	$tab = 'policy';
}

$tab_help = array(
	'policy'               => array(
		'label'       => __( 'Policy', 'vcns-security-automation-manager' ),
		'description' => __( 'Per-surface mode and thresholds. Observe mode never blocks a visitor -- it only records what would have happened.', 'vcns-security-automation-manager' ),
	),
	'ip-rules'             => array(
		'label'       => __( 'IP Rules', 'vcns-security-automation-manager' ),
		'description' => __( 'A manual allow/block list. These are explicit decisions and apply regardless of a surface\'s observe/enforce mode.', 'vcns-security-automation-manager' ),
	),
	'blocks'               => array(
		'label'       => __( 'Blocks', 'vcns-security-automation-manager' ),
		'description' => __( 'Sources currently escalated by automatic detection, and the ones you\'ve made permanent.', 'vcns-security-automation-manager' ),
	),
	'network-intelligence' => array(
		'label'       => __( 'Network Intelligence', 'vcns-security-automation-manager' ),
		'description' => __( 'Observation-only network-level facts -- Tor exit status, ASN, and (opt-in) Geo-IP. Never implies malicious intent and never blocks on its own.', 'vcns-security-automation-manager' ),
	),
	'detectors'            => array(
		'label'       => __( 'Detectors', 'vcns-security-automation-manager' ),
		'description' => __( 'Enable or disable individual detector families, and -- where a family allows it -- opt a family into contributing to progressive blocking instead of pure observation.', 'vcns-security-automation-manager' ),
	),
	'custom-rules'         => array(
		'label'       => __( 'Custom Rules', 'vcns-security-automation-manager' ),
		'description' => __( 'Your own regex-based detection rules, similar to a fail2ban filter -- a rule you add here appears on the Detectors tab like any built-in family, so it can be enabled/disabled and opted into enforcement the same way.', 'vcns-security-automation-manager' ),
	),
);
?>
<div class="wrap wp-sam-wrap">
	<h1><?php esc_html_e( 'Traffic Controls', 'vcns-security-automation-manager' ); ?></h1>

	<p>
		<?php esc_html_e( 'Rate limiting and progressive blocking, independent of the header policies above. Every surface starts in Observe mode and stays there until you explicitly switch it to Enforce.', 'vcns-security-automation-manager' ); ?>
	</p>

	<nav class="nav-tab-wrapper wp-sam-tab-wrapper" role="tablist" aria-label="<?php esc_attr_e( 'Traffic Controls sections', 'vcns-security-automation-manager' ); ?>">
		<?php foreach ( $tab_help as $tab_key => $tab_data ) : ?>
		<a class="nav-tab<?php echo $tab_key === $tab ? ' nav-tab-active' : ''; ?>"
			href="<?php echo esc_url( add_query_arg( 'tab', $tab_key, $base_url ) ); ?>"
			role="tab"
			title="<?php echo esc_attr( $tab_data['description'] ); ?>"
			<?php echo $tab_key === $tab ? 'aria-selected="true" aria-current="page"' : 'aria-selected="false"'; ?>>
			<?php echo esc_html( $tab_data['label'] ); ?>
		</a>
		<?php endforeach; ?>
	</nav>
	<div class="wp-sam-tab-help" role="note">
		<strong><?php echo esc_html( $tab_help[ $tab ]['label'] ); ?>:</strong>
		<?php echo esc_html( $tab_help[ $tab ]['description'] ); ?>
	</div>

	<?php if ( 'policy' === $tab ) : ?>

		<?php $policies = ( new Traffic_Policy_Store() )->all(); ?>

		<p class="description">
			<?php esc_html_e( "Each surface below -- frontend, admin, login, and the REST API -- gets its own rate limit, because what counts as normal traffic on one is an attack on another: a handful of requests a minute is unremarkable on the frontend but alarming against the login form. In Observe mode, crossing that limit is only ever recorded, never enforced. In Enforce mode, a source that crosses it climbs a progressive ladder instead -- warned, then throttled, then temporarily blocked, then blocked for longer -- visible per-source on the Blocks tab, so one burst of ordinary traffic isn't treated the same as a sustained attack. Each quiet hour after that steps the source back down one stage, and a logged-in administrator's own requests never count towards the limit. Login also gets a failed-attempt lockout, since brute-forcing a password is a pattern rate limiting alone doesn't fully capture.", 'vcns-security-automation-manager' ); ?>
		</p>

		<?php foreach ( $policies as $policy ) : ?>
		<form id="wp-sam-policy-form-<?php echo esc_attr( (string) $policy['surface'] ); ?>" method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
			<?php wp_nonce_field( 'wp_sam_traffic_policy_update' ); ?>
			<input type="hidden" name="action" value="wp_sam_traffic_policy_update" />
			<input type="hidden" name="surface" value="<?php echo esc_attr( (string) $policy['surface'] ); ?>" />
			<?php if ( 'login' !== $policy['surface'] ) : ?>
			<input type="hidden" name="login_max_failed_attempts" value="<?php echo esc_attr( (string) $policy['login_max_failed_attempts'] ); ?>" />
			<input type="hidden" name="login_lockout_seconds" value="<?php echo esc_attr( (string) $policy['login_lockout_seconds'] ); ?>" />
			<?php endif; ?>
		</form>
		<?php endforeach; ?>

		<div class="wp-sam-table-wrap">
		<table class="widefat striped wp-sam-table wp-sam-policy-table" style="margin-top:1em">
			<thead>
				<tr>
					<th class="wp-sam-col-surface"><?php esc_html_e( 'Surface', 'vcns-security-automation-manager' ); ?></th>
					<th class="wp-sam-col-status"><?php esc_html_e( 'Mode', 'vcns-security-automation-manager' ); ?></th>
					<th class="wp-sam-col-technical"><?php esc_html_e( 'Rate limit', 'vcns-security-automation-manager' ); ?></th>
					<th class="wp-sam-col-technical"><?php esc_html_e( 'Failed login lockout', 'vcns-security-automation-manager' ); ?></th>
					<th class="wp-sam-col-actions"><?php esc_html_e( 'Actions', 'vcns-security-automation-manager' ); ?></th>
				</tr>
			</thead>
			<tbody>
			<?php foreach ( $policies as $policy ) : ?>
				<?php $form_id = 'wp-sam-policy-form-' . (string) $policy['surface']; ?>
				<tr>
					<td class="wp-sam-col-surface"><?php echo esc_html( ucfirst( (string) $policy['surface'] ) ); ?></td>
					<td class="wp-sam-col-status">
						<select form="<?php echo esc_attr( $form_id ); ?>" name="mode">
							<option value="observe" <?php selected( $policy['mode'], 'observe' ); ?>><?php esc_html_e( 'Observe (never blocks)', 'vcns-security-automation-manager' ); ?></option>
							<option value="enforce" <?php selected( $policy['mode'], 'enforce' ); ?>><?php esc_html_e( 'Enforce', 'vcns-security-automation-manager' ); ?></option>
						</select>
					</td>
					<td class="wp-sam-col-technical">
						<input type="number" min="1" form="<?php echo esc_attr( $form_id ); ?>" name="rate_limit_max_requests" style="width:80px" value="<?php echo esc_attr( (string) $policy['rate_limit_max_requests'] ); ?>" />
						<?php esc_html_e( 'per', 'vcns-security-automation-manager' ); ?>
						<input type="number" min="1" form="<?php echo esc_attr( $form_id ); ?>" name="rate_limit_window_seconds" style="width:80px" value="<?php echo esc_attr( (string) $policy['rate_limit_window_seconds'] ); ?>" />
						<?php esc_html_e( 'sec', 'vcns-security-automation-manager' ); ?>
					</td>
					<td class="wp-sam-col-technical">
						<?php if ( 'login' === $policy['surface'] ) : ?>
						<input type="number" min="1" form="<?php echo esc_attr( $form_id ); ?>" name="login_max_failed_attempts" style="width:70px" value="<?php echo esc_attr( (string) $policy['login_max_failed_attempts'] ); ?>" />
							<?php esc_html_e( 'in', 'vcns-security-automation-manager' ); ?>
						<input type="number" min="1" form="<?php echo esc_attr( $form_id ); ?>" name="login_lockout_seconds" style="width:80px" value="<?php echo esc_attr( (string) $policy['login_lockout_seconds'] ); ?>" />
							<?php esc_html_e( 'sec', 'vcns-security-automation-manager' ); ?>
						<?php else : ?>
						&#8212;
						<?php endif; ?>
					</td>
					<td class="wp-sam-col-actions"><button type="submit" form="<?php echo esc_attr( $form_id ); ?>" class="button button-primary"><?php esc_html_e( 'Save', 'vcns-security-automation-manager' ); ?></button></td>
				</tr>
			<?php endforeach; ?>
			</tbody>
		</table>
		</div>

	<?php elseif ( 'ip-rules' === $tab ) : ?>

		<?php $rules = ( new Ip_Rule_Store() )->all(); ?>

		<p class="description">
			<?php esc_html_e( 'Use this when you already know a specific address and want a decision that doesn\'t depend on rate limits or detectors at all: Allow permanently exempts a source you trust (a monitoring service, your own office) from every other control on this page; Block permanently shuts one out, regardless of what mode a surface is in. A CIDR range lets one rule cover a whole block of addresses at once -- 203.0.113.0/24 covers all 256 addresses from .0 to .255, useful when an attacker is rotating through a known range. Leave Expires blank (or 0) for a rule that should never lapse on its own; for the equivalent decision by ASN or country instead of by address, see Network Rules on the Network Intelligence tab.', 'vcns-security-automation-manager' ); ?>
		</p>

		<div class="wp-sam-table-wrap">
		<table class="widefat striped wp-sam-table wp-sam-violations-table" style="margin-top:1em">
			<thead>
				<tr>
					<th class="wp-sam-col-status"><?php esc_html_e( 'Type', 'vcns-security-automation-manager' ); ?></th>
					<th class="wp-sam-col-technical"><?php esc_html_e( 'CIDR', 'vcns-security-automation-manager' ); ?></th>
					<th class="wp-sam-col-surface"><?php esc_html_e( 'Surface', 'vcns-security-automation-manager' ); ?></th>
					<th class="wp-sam-col-description"><?php esc_html_e( 'Reason', 'vcns-security-automation-manager' ); ?></th>
					<th class="wp-sam-col-datetime"><?php esc_html_e( 'Expires', 'vcns-security-automation-manager' ); ?></th>
					<th class="wp-sam-col-actions"><?php esc_html_e( 'Actions', 'vcns-security-automation-manager' ); ?></th>
				</tr>
			</thead>
			<tbody>
			<?php foreach ( $rules as $rule ) : ?>
			<tr>
				<td class="wp-sam-col-status"><?php echo esc_html( ucfirst( (string) $rule['list_type'] ) ); ?></td>
				<td class="wp-sam-col-technical"><code><?php echo esc_html( (string) $rule['cidr'] ); ?></code></td>
				<td class="wp-sam-col-surface"><?php echo esc_html( '' !== (string) $rule['surface'] ? ucfirst( (string) $rule['surface'] ) : __( 'All', 'vcns-security-automation-manager' ) ); ?></td>
				<td class="wp-sam-col-description"><?php echo esc_html( (string) $rule['reason'] ); ?></td>
				<td class="wp-sam-col-datetime"><?php echo esc_html( ! empty( $rule['expires_at'] ) ? (string) $rule['expires_at'] : __( 'Never', 'vcns-security-automation-manager' ) ); ?></td>
				<td class="wp-sam-col-actions">
					<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" style="display:inline">
						<?php wp_nonce_field( 'wp_sam_ip_rule_delete' ); ?>
						<input type="hidden" name="action" value="wp_sam_ip_rule_delete" />
						<input type="hidden" name="rule_id" value="<?php echo esc_attr( (string) $rule['id'] ); ?>" />
						<?php submit_button( __( 'Delete', 'vcns-security-automation-manager' ), 'link-delete small', '', false ); ?>
					</form>
				</td>
			</tr>
			<?php endforeach; ?>
			<?php if ( empty( $rules ) ) : ?>
			<tr>
				<td colspan="6"><p><?php esc_html_e( 'No IP rules yet.', 'vcns-security-automation-manager' ); ?></p></td>
			</tr>
			<?php endif; ?>
			</tbody>
		</table>
		</div>

		<h2 id="wp-sam-ip-rule-add" style="margin-top:2em"><?php esc_html_e( 'Add a rule', 'vcns-security-automation-manager' ); ?></h2>

		<?php
		// Same "never delete on a GET render" reasoning as the Geo-IP tab's
		// pending-lockout transient: only handle_ip_rule_add()'s own
		// successful add clears this key; the 5-minute TTL handles the rest.
		$ip_rule_lockout_pending = get_transient( Admin_UI::IP_RULE_LOCKOUT_TRANSIENT_PREFIX . get_current_user_id() );
		$ip_rule_confirming      = is_array( $ip_rule_lockout_pending );

		$ip_rule_form_defaults = array(
			'list_type'        => 'block',
			'cidr'             => '',
			'surface'          => '',
			'reason'           => '',
			'expires_in_hours' => 0,
		);
		if ( $ip_rule_confirming ) {
			$ip_rule_form_defaults = array_merge( $ip_rule_form_defaults, $ip_rule_lockout_pending );
		} elseif ( isset( $_GET['cidr'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- pre-fills the form (e.g. "Block IP" on ASN Lookup); nothing is saved until it's submitted.
			$ip_rule_form_defaults['cidr']   = sanitize_text_field( wp_unslash( $_GET['cidr'] ) ); // phpcs:ignore WordPress.Security.NonceVerification.Recommended
			$ip_rule_form_defaults['reason'] = sanitize_text_field( wp_unslash( $_GET['reason'] ?? '' ) ); // phpcs:ignore WordPress.Security.NonceVerification.Recommended
		}
		?>

		<?php if ( $ip_rule_confirming ) : ?>
		<div class="notice notice-warning inline" style="padding:12px 16px;margin:1em 0">
			<p style="margin-top:0"><strong><?php esc_html_e( 'This would block you:', 'vcns-security-automation-manager' ); ?></strong> <?php echo esc_html( (string) $ip_rule_lockout_pending['message'] ); ?></p>
		</div>
		<?php endif; ?>

		<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
			<?php wp_nonce_field( 'wp_sam_ip_rule_add' ); ?>
			<input type="hidden" name="action" value="wp_sam_ip_rule_add" />
			<table class="form-table">
				<tr>
					<th><label for="list_type"><?php esc_html_e( 'Type', 'vcns-security-automation-manager' ); ?></label></th>
					<td>
						<select id="list_type" name="list_type">
							<option value="block" <?php selected( $ip_rule_form_defaults['list_type'], 'block' ); ?>><?php esc_html_e( 'Block', 'vcns-security-automation-manager' ); ?></option>
							<option value="allow" <?php selected( $ip_rule_form_defaults['list_type'], 'allow' ); ?>><?php esc_html_e( 'Allow', 'vcns-security-automation-manager' ); ?></option>
						</select>
					</td>
				</tr>
				<tr>
					<th><label for="cidr"><?php esc_html_e( 'IP or CIDR', 'vcns-security-automation-manager' ); ?></label></th>
					<td><input type="text" id="cidr" name="cidr" required placeholder="203.0.113.42 or 203.0.113.0/24" style="width:100%;max-width:300px" value="<?php echo esc_attr( (string) $ip_rule_form_defaults['cidr'] ); ?>" /></td>
				</tr>
				<tr>
					<th><label for="surface"><?php esc_html_e( 'Surface', 'vcns-security-automation-manager' ); ?></label></th>
					<td>
						<select id="surface" name="surface">
							<option value="" <?php selected( $ip_rule_form_defaults['surface'], '' ); ?>><?php esc_html_e( 'All surfaces', 'vcns-security-automation-manager' ); ?></option>
							<?php foreach ( array( 'frontend', 'admin', 'login', 'api' ) as $s ) : ?>
							<option value="<?php echo esc_attr( $s ); ?>" <?php selected( $ip_rule_form_defaults['surface'], $s ); ?>><?php echo esc_html( ucfirst( $s ) ); ?></option>
							<?php endforeach; ?>
						</select>
					</td>
				</tr>
				<tr>
					<th><label for="reason"><?php esc_html_e( 'Reason', 'vcns-security-automation-manager' ); ?></label></th>
					<td><input type="text" id="reason" name="reason" required style="width:100%;max-width:300px" value="<?php echo esc_attr( (string) $ip_rule_form_defaults['reason'] ); ?>" /></td>
				</tr>
				<tr>
					<th><label for="expires_in_hours"><?php esc_html_e( 'Expires after (hours)', 'vcns-security-automation-manager' ); ?></label></th>
					<td><input type="number" id="expires_in_hours" name="expires_in_hours" min="0" placeholder="<?php esc_attr_e( '0 = never', 'vcns-security-automation-manager' ); ?>" style="width:120px" value="<?php echo (int) $ip_rule_form_defaults['expires_in_hours'] > 0 ? esc_attr( (string) (int) $ip_rule_form_defaults['expires_in_hours'] ) : ''; ?>" /></td>
				</tr>
				<?php if ( $ip_rule_confirming ) : ?>
				<tr>
					<th></th>
					<td>
						<label>
							<input type="checkbox" name="confirm_lockout_risk" value="1" />
							<?php esc_html_e( 'I understand this will block my own address -- add it anyway.', 'vcns-security-automation-manager' ); ?>
						</label>
					</td>
				</tr>
				<?php endif; ?>
			</table>
			<?php submit_button( __( 'Add rule', 'vcns-security-automation-manager' ) ); ?>
		</form>

		<?php
		$own_addresses = Own_Address_Store::all();
		$own_rejected  = get_transient( 'wp_sam_own_addresses_rejected_' . get_current_user_id() );
		if ( false !== $own_rejected ) {
			delete_transient( 'wp_sam_own_addresses_rejected_' . get_current_user_id() );
		}
		$own_suggested = array_values( array_diff( ( new Scanner_Identity_Store() )->recent_wp_cron_callers(), $own_addresses ) );
		?>
		<h2 id="wp-sam-own-addresses" style="margin-top:2em"><?php esc_html_e( 'This site\'s own addresses', 'vcns-security-automation-manager' ); ?></h2>
		<p class="description">
			<?php esc_html_e( 'If this site\'s own servers or containers reach it through a public IP address, list those addresses here. They are then treated like a private address: never rate-limited or blocked automatically, never counted into a campaign, and shown on Observe → Continuous Intelligence → Identities as this site\'s own. An Allow rule above only stops this page blocking an address; an address listed here also stops showing up as escalating. A Block rule above still applies. Private and loopback addresses (10.x, 172.16-31.x, 192.168.x, 127.x and the IPv6 equivalents) are already covered and don\'t need listing.', 'vcns-security-automation-manager' ); ?>
		</p>
		<?php if ( is_array( $own_rejected ) && ! empty( $own_rejected ) ) : ?>
		<div class="notice notice-warning inline">
			<p><?php esc_html_e( 'These entries were not saved:', 'vcns-security-automation-manager' ); ?></p>
			<ul>
				<?php foreach ( $own_rejected as $rejected ) : ?>
				<li><code><?php echo esc_html( (string) ( $rejected['entry'] ?? '' ) ); ?></code> -- <?php echo esc_html( (string) ( $rejected['reason'] ?? '' ) ); ?></li>
				<?php endforeach; ?>
			</ul>
		</div>
		<?php elseif ( isset( $_GET['own_saved'] ) ) : // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- display-only flag set by our own redirect. ?>
			<?php $own_relabelled = isset( $_GET['own_relabelled'] ) ? absint( $_GET['own_relabelled'] ) : 0; // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- display-only count set by our own redirect. ?>
		<div class="notice notice-success inline"><p>
			<?php esc_html_e( 'Saved.', 'vcns-security-automation-manager' ); ?>
			<?php if ( $own_relabelled > 0 ) : ?>
				<?php
				/* translators: %d: number of identities whose label changed. */
				echo esc_html( sprintf( _n( '%d identity on Observe → Continuous Intelligence → Identities was relabelled to match.', '%d identities on Observe → Continuous Intelligence → Identities were relabelled to match.', $own_relabelled, 'vcns-security-automation-manager' ), $own_relabelled ) );
				?>
			<?php endif; ?>
		</p></div>
		<?php endif; ?>
		<?php if ( ! empty( $own_suggested ) ) : ?>
		<p class="description">
			<?php
			printf(
				/* translators: %s: comma-separated IP addresses. */
				esc_html__( 'Seen calling /wp-cron.php in the last 30 days: %s. WordPress normally only calls that on itself, so these are probably this site\'s own servers. Check each one before adding it: an external cron service calls it too.', 'vcns-security-automation-manager' ),
				'<code>' . implode( '</code>, <code>', array_map( 'esc_html', $own_suggested ) ) . '</code>' // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- each address is escaped with esc_html().
			);
			?>
		</p>
		<?php endif; ?>
		<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
			<?php wp_nonce_field( 'wp_sam_own_addresses_save' ); ?>
			<input type="hidden" name="action" value="wp_sam_own_addresses_save" />
			<p>
				<label for="own_addresses"><?php esc_html_e( 'One IP address or CIDR range per line', 'vcns-security-automation-manager' ); ?></label><br />
				<textarea id="own_addresses" name="own_addresses" rows="4" style="width:100%;max-width:300px" placeholder="203.0.113.10&#10;203.0.113.32/28"><?php echo esc_textarea( implode( "\n", $own_addresses ) ); ?></textarea>
			</p>
			<?php submit_button( __( 'Save own addresses', 'vcns-security-automation-manager' ) ); ?>
		</form>

	<?php elseif ( 'blocks' === $tab ) : ?>

		<?php $blocks = ( new Traffic_Block_Store() )->all_active(); ?>

		<p class="description">
			<?php esc_html_e( "This is what automatic detection has done on its own, without you adding anything here -- crossing a rate limit or tripping an enforce-mode detector moves a source up a stage (Warn, Throttle, Temporary block, Extended block), and every hour without a new violation, once any block has ended, moves it back down one; Occurrences counts how many times that's happened. Release lifts a block immediately, useful when you recognise a source as a false positive; Make Permanent turns a temporary, auto-expiring block into one that stays until you remove it yourself -- functionally the same outcome as adding it to IP Rules by hand. Nothing here is a manual decision until you click one of those two buttons.", 'vcns-security-automation-manager' ); ?>
		</p>

		<div class="wp-sam-table-wrap">
		<table class="widefat striped wp-sam-table wp-sam-violations-table wp-sam-blocks-table" style="margin-top:1em">
			<thead>
				<tr>
					<th class="wp-sam-col-technical"><?php esc_html_e( 'IP', 'vcns-security-automation-manager' ); ?></th>
					<th class="wp-sam-col-surface"><?php esc_html_e( 'Surface', 'vcns-security-automation-manager' ); ?></th>
					<th class="wp-sam-col-status"><?php esc_html_e( 'Stage', 'vcns-security-automation-manager' ); ?></th>
					<th class="wp-sam-col-description"><?php esc_html_e( 'Reason', 'vcns-security-automation-manager' ); ?></th>
					<th class="wp-sam-col-count"><?php esc_html_e( 'Occurrences', 'vcns-security-automation-manager' ); ?></th>
					<th class="wp-sam-col-datetime"><?php esc_html_e( 'Blocked Until', 'vcns-security-automation-manager' ); ?></th>
					<th class="wp-sam-col-actions"><?php esc_html_e( 'Actions', 'vcns-security-automation-manager' ); ?></th>
				</tr>
			</thead>
			<tbody>
			<?php foreach ( $blocks as $block ) : ?>
			<tr>
				<td class="wp-sam-col-technical"><code><?php echo esc_html( (string) $block['ip'] ); ?></code></td>
				<td class="wp-sam-col-surface"><?php echo esc_html( ucfirst( (string) $block['surface'] ) ); ?></td>
				<td class="wp-sam-col-status"><?php echo esc_html( str_replace( '_', ' ', ucfirst( (string) $block['stage'] ) ) ); ?></td>
				<td class="wp-sam-col-description"><?php echo esc_html( str_replace( '_', ' ', (string) $block['reason'] ) ); ?></td>
				<td class="wp-sam-col-count"><?php echo esc_html( number_format( (int) $block['occurrence_count'] ) ); ?></td>
				<?php
				$blocked_until_display = '—';
				if ( ! empty( $block['is_persistent'] ) ) {
					$blocked_until_display = __( 'Permanent', 'vcns-security-automation-manager' );
				} elseif ( ! empty( $block['blocked_until'] ) ) {
					$blocked_until_display = (string) $block['blocked_until'];
				}
				?>
				<td class="wp-sam-col-datetime"><?php echo esc_html( $blocked_until_display ); ?></td>
				<td class="wp-sam-col-actions">
					<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" style="display:inline">
						<?php wp_nonce_field( 'wp_sam_traffic_block_release' ); ?>
						<input type="hidden" name="action" value="wp_sam_traffic_block_release" />
						<input type="hidden" name="block_id" value="<?php echo esc_attr( (string) $block['id'] ); ?>" />
						<?php submit_button( __( 'Release', 'vcns-security-automation-manager' ), 'secondary small', '', false ); ?>
					</form>
					<?php if ( empty( $block['is_persistent'] ) ) : ?>
					<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" style="display:inline">
						<?php wp_nonce_field( 'wp_sam_traffic_block_persist' ); ?>
						<input type="hidden" name="action" value="wp_sam_traffic_block_persist" />
						<input type="hidden" name="block_id" value="<?php echo esc_attr( (string) $block['id'] ); ?>" />
						<?php submit_button( __( 'Make Permanent', 'vcns-security-automation-manager' ), 'secondary small', '', false ); ?>
					</form>
					<?php endif; ?>
				</td>
			</tr>
			<?php endforeach; ?>
			<?php if ( empty( $blocks ) ) : ?>
			<tr>
				<td colspan="7"><p><?php esc_html_e( 'No active blocks.', 'vcns-security-automation-manager' ); ?></p></td>
			</tr>
			<?php endif; ?>
			</tbody>
		</table>
		</div>

	<?php elseif ( 'network-intelligence' === $tab ) : ?>

		<?php
		// A pre-existing bookmarked/scripted link carrying ?lookup_ip= or
		// ?geo_lookup_ip= (both valid before Network Intelligence had
		// sub-tabs) has no way to also carry a &subtab= it never needed --
		// defaulting to the sub-tab that param actually belongs to, rather
		// than always 'tor', keeps such a link doing what it always did
		// instead of silently landing on the wrong section with the lookup
		// parameter never even read.
		$ni_default_subtab = 'tor';
		if ( isset( $_GET['geo_lookup_ip'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended
			$ni_default_subtab = 'geoip';
		} elseif ( isset( $_GET['lookup_ip'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended
			$ni_default_subtab = 'asn';
		}

		$ni_subtab          = isset( $_GET['subtab'] ) ? sanitize_text_field( wp_unslash( $_GET['subtab'] ) ) : $ni_default_subtab; // phpcs:ignore WordPress.Security.NonceVerification.Recommended
		$ni_allowed_subtabs = array( 'tor', 'asn', 'geoip', 'well-known', 'network-rules' );
		if ( ! in_array( $ni_subtab, $ni_allowed_subtabs, true ) ) {
			$ni_subtab = 'tor';
		}
		$ni_subtab_labels = array(
			'tor'           => __( 'Tor Exit List', 'vcns-security-automation-manager' ),
			'asn'           => __( 'ASN Lookup', 'vcns-security-automation-manager' ),
			'geoip'         => __( 'Geo-IP', 'vcns-security-automation-manager' ),
			'well-known'    => __( 'Well-Known Files', 'vcns-security-automation-manager' ),
			'network-rules' => __( 'Network Rules', 'vcns-security-automation-manager' ),
		);
		$ni_base_url      = add_query_arg( 'tab', 'network-intelligence', $base_url );
		?>

		<nav class="nav-tab-wrapper wp-sam-tab-wrapper wp-sam-subtab-wrapper" role="tablist" aria-label="<?php esc_attr_e( 'Network Intelligence sections', 'vcns-security-automation-manager' ); ?>">
			<?php foreach ( $ni_subtab_labels as $ni_subtab_key => $ni_subtab_label ) : ?>
			<a class="nav-tab<?php echo $ni_subtab_key === $ni_subtab ? ' nav-tab-active' : ''; ?>"
				href="<?php echo esc_url( add_query_arg( 'subtab', $ni_subtab_key, $ni_base_url ) ); ?>"
				role="tab"
				<?php echo $ni_subtab_key === $ni_subtab ? 'aria-selected="true" aria-current="page"' : 'aria-selected="false"'; ?>>
				<?php echo esc_html( $ni_subtab_label ); ?>
			</a>
			<?php endforeach; ?>
		</nav>

		<div class="wp-sam-subtab-content">

		<?php if ( 'tor' === $ni_subtab ) : ?>

			<?php
			$tor_store  = new Tor_Exit_List_Store();
			$tor_status = $tor_store->last_fetch_status();
			?>

			<div class="wp-sam-table-wrap">
			<table class="widefat striped wp-sam-table wp-sam-tor-table" style="margin-top:1em">
				<thead>
					<tr>
						<th class="wp-sam-col-primary"><?php esc_html_e( 'Source', 'vcns-security-automation-manager' ); ?></th>
						<th class="wp-sam-col-count"><?php esc_html_e( 'Known exit nodes', 'vcns-security-automation-manager' ); ?></th>
						<th class="wp-sam-col-datetime"><?php esc_html_e( 'Last refreshed', 'vcns-security-automation-manager' ); ?></th>
						<th class="wp-sam-col-status"><?php esc_html_e( 'Last fetch status', 'vcns-security-automation-manager' ); ?></th>
						<th class="wp-sam-col-description"><?php esc_html_e( 'About', 'vcns-security-automation-manager' ); ?></th>
						<th class="wp-sam-col-actions"><?php esc_html_e( 'Action', 'vcns-security-automation-manager' ); ?></th>
					</tr>
				</thead>
				<tbody>
					<tr>
						<td class="wp-sam-col-primary"><?php esc_html_e( 'Tor Project exit-node list', 'vcns-security-automation-manager' ); ?></td>
						<td class="wp-sam-col-count"><?php echo esc_html( number_format( $tor_store->count() ) ); ?></td>
						<td class="wp-sam-col-datetime"><?php echo esc_html( $tor_store->last_refreshed_at() ?? __( 'Never', 'vcns-security-automation-manager' ) ); ?></td>
						<td class="wp-sam-col-status"><?php echo esc_html( '' !== $tor_status ? ucfirst( $tor_status ) : __( 'Not yet run', 'vcns-security-automation-manager' ) ); ?></td>
						<td class="wp-sam-col-description"><?php esc_html_e( 'Refreshed automatically once a day from the Tor Project\'s own public exit-node list. Tor identity is recorded as context on evidence a detector already produced -- it never implies malicious intent on its own, and nothing here blocks a visitor.', 'vcns-security-automation-manager' ); ?></td>
						<td class="wp-sam-col-actions">
							<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" style="display:inline">
								<?php wp_nonce_field( 'wp_sam_tor_list_refresh' ); ?>
								<input type="hidden" name="action" value="wp_sam_tor_list_refresh" />
								<?php submit_button( __( 'Refresh Now', 'vcns-security-automation-manager' ), 'secondary small', '', false ); ?>
							</form>
						</td>
					</tr>
				</tbody>
			</table>
			</div>

		<?php elseif ( 'asn' === $ni_subtab ) : ?>

			<?php $asn_profile = isset( $_GET['asn'] ) ? absint( ltrim( strtoupper( sanitize_text_field( wp_unslash( $_GET['asn'] ) ) ), 'AS' ) ) : 0; // phpcs:ignore WordPress.Security.NonceVerification.Recommended ?>

			<?php if ( $asn_profile > 0 ) : ?>

				<?php require __DIR__ . '/partials/asn-profile.php'; ?>

			<?php else : ?>

				<p class="description">
					<?php esc_html_e( 'Free, unauthenticated lookup via Team Cymru -- no account needed. Results are cached for 30 days once looked up, so this only costs a real DNS query the first time a given IP is involved in a detector match.', 'vcns-security-automation-manager' ); ?>
				</p>

				<form method="get" class="wp-sam-inline-form" style="margin-top:1em">
					<input type="hidden" name="page" value="security-automation-manager-traffic" />
					<input type="hidden" name="tab" value="network-intelligence" />
					<input type="hidden" name="subtab" value="asn" />
					<label for="lookup_ip" class="screen-reader-text"><?php esc_html_e( 'IP address to look up', 'vcns-security-automation-manager' ); ?></label>
					<input type="text" id="lookup_ip" name="lookup_ip" placeholder="203.0.113.42" value="<?php echo esc_attr( isset( $_GET['lookup_ip'] ) ? sanitize_text_field( wp_unslash( $_GET['lookup_ip'] ) ) : '' ); // phpcs:ignore WordPress.Security.NonceVerification.Recommended ?>" style="width:220px" />
					<?php submit_button( __( 'Look Up', 'vcns-security-automation-manager' ), 'secondary', '', false ); ?>
				</form>

				<?php
				$lookup_ip = isset( $_GET['lookup_ip'] ) ? sanitize_text_field( wp_unslash( $_GET['lookup_ip'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Recommended
				if ( '' !== $lookup_ip ) :
					$asn_store      = new Asn_Lookup_Store();
					$lookup_result  = $asn_store->resolve( $lookup_ip );
					$lookup_asn     = $lookup_result['asn'];
					$lookup_range   = null !== $lookup_asn ? $asn_store->network_range( $lookup_ip ) : null;
					$lookup_is_ip   = false !== filter_var( $lookup_ip, FILTER_VALIDATE_IP );
					$lookup_is_own  = $lookup_is_ip && Ip_Resolver::resolve() === $lookup_ip;
					$lookup_ip_rule = $lookup_is_ip ? ( new Ip_Rule_Store() )->match( $lookup_ip, '' ) : null;
					$lookup_blocked = null !== $lookup_ip_rule && 'block' === $lookup_ip_rule['list_type'];
					$lookup_as_rule = null !== $lookup_asn ? ( new Network_Rule_Store() )->match( $lookup_asn, null, '' ) : null;
					$lookup_reason  = null !== $lookup_asn
						/* translators: 1: AS number, e.g. 15169; 2: the organisation that holds it */
						? sprintf( __( 'Looked up on ASN Lookup: AS%1$d, %2$s', 'vcns-security-automation-manager' ), $lookup_asn, $lookup_result['asn_org'] ?? '' )
						: __( 'Looked up on ASN Lookup', 'vcns-security-automation-manager' );
					$lookup_rule_url    = static fn( string $cidr ): string => add_query_arg(
						array(
							'tab'    => 'ip-rules',
							'cidr'   => $cidr,
							'reason' => $lookup_reason,
						),
						$base_url
					) . '#wp-sam-ip-rule-add';
					$lookup_profile_url = add_query_arg(
						array(
							'subtab'    => 'asn',
							'asn'       => $lookup_asn,
							'lookup_ip' => $lookup_ip,
						),
						$ni_base_url
					);
					$lookup_as_rule_url = add_query_arg(
						array(
							'subtab'      => 'network-rules',
							'rule_type'   => 'asn',
							'rule_value'  => 'AS' . $lookup_asn,
							'rule_reason' => $lookup_reason,
						),
						$ni_base_url
					) . '#wp-sam-network-rule-add';
					?>
				<div class="wp-sam-table-wrap">
				<table class="widefat striped wp-sam-table wp-sam-asn-result-table" style="margin-top:1em">
					<thead>
						<tr>
							<th class="wp-sam-col-technical"><?php esc_html_e( 'IP', 'vcns-security-automation-manager' ); ?></th>
							<th class="wp-sam-col-technical"><?php esc_html_e( 'Network range', 'vcns-security-automation-manager' ); ?></th>
							<th class="wp-sam-col-compact"><?php esc_html_e( 'ASN', 'vcns-security-automation-manager' ); ?></th>
							<th class="wp-sam-col-description"><?php esc_html_e( 'Organisation', 'vcns-security-automation-manager' ); ?></th>
							<th class="wp-sam-col-actions"><?php esc_html_e( 'Actions', 'vcns-security-automation-manager' ); ?></th>
						</tr>
					</thead>
					<tbody>
						<tr>
							<td class="wp-sam-col-technical">
								<code><?php echo esc_html( $lookup_ip ); ?></code>
								<?php if ( $lookup_is_own ) : ?>
								<br /><span class="description"><?php esc_html_e( 'Your current address', 'vcns-security-automation-manager' ); ?></span>
								<?php endif; ?>
							</td>
							<td class="wp-sam-col-technical"><?php echo null !== $lookup_range ? '<code>' . esc_html( $lookup_range ) . '</code>' : '&#8212;'; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- static em-dash literal; the range itself is escaped. ?></td>
							<td class="wp-sam-col-compact">
								<?php if ( null !== $lookup_asn ) : ?>
								<a href="<?php echo esc_url( $lookup_profile_url ); ?>" title="<?php esc_attr_e( 'More about this network', 'vcns-security-automation-manager' ); ?>"><?php echo esc_html( 'AS' . (string) $lookup_asn ); ?></a>
								<?php else : ?>
									<?php esc_html_e( 'Not found', 'vcns-security-automation-manager' ); ?>
								<?php endif; ?>
							</td>
							<td class="wp-sam-col-description"><?php echo esc_html( $lookup_result['asn_org'] ?? '—' ); ?></td>
							<td class="wp-sam-col-actions">
								<?php if ( $lookup_blocked ) : ?>
								<span class="description"><?php esc_html_e( 'IP blocked', 'vcns-security-automation-manager' ); ?></span>
								<?php elseif ( $lookup_is_ip ) : ?>
								<a class="button button-small" href="<?php echo esc_url( $lookup_rule_url( $lookup_ip ) ); ?>"><?php esc_html_e( 'Block IP', 'vcns-security-automation-manager' ); ?></a>
									<?php if ( null !== $lookup_range ) : ?>
								<a class="button button-small" href="<?php echo esc_url( $lookup_rule_url( $lookup_range ) ); ?>"><?php esc_html_e( 'Block range', 'vcns-security-automation-manager' ); ?></a>
									<?php endif; ?>
								<?php endif; ?>
								<?php if ( null !== $lookup_as_rule ) : ?>
								<span class="description">
									<?php
									/* translators: %d: AS number, e.g. 15169 */
									echo esc_html( sprintf( __( 'AS%d blocked', 'vcns-security-automation-manager' ), $lookup_asn ) );
									?>
								</span>
								<?php elseif ( null !== $lookup_asn ) : ?>
								<a class="button button-small" href="<?php echo esc_url( $lookup_as_rule_url ); ?>">
									<?php
									/* translators: %d: AS number, e.g. 15169 */
									echo esc_html( sprintf( __( 'Block AS%d', 'vcns-security-automation-manager' ), $lookup_asn ) );
									?>
								</a>
								<?php endif; ?>
							</td>
						</tr>
					</tbody>
				</table>
				</div>
					<?php if ( false === filter_var( $lookup_ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 ) ) : ?>
				<p class="description"><?php esc_html_e( 'ASN Lookup works for IPv4 addresses only.', 'vcns-security-automation-manager' ); ?></p>
					<?php endif; ?>
				<?php endif; ?>

			<?php endif; ?>

		<?php elseif ( 'geoip' === $ni_subtab ) : ?>

			<?php
			$geo_store           = new Geo_Ip_Store();
			$geo_configured      = $geo_store->is_configured();
			$geoip_country_names = Iso_Countries::all();
			$geoip_site_country  = Site_Country::get();
			?>

			<?php if ( isset( $_GET['settings_saved'] ) ) : // phpcs:ignore WordPress.Security.NonceVerification.Recommended ?>
			<div class="notice notice-success inline"><p><?php esc_html_e( 'Geo-IP settings saved.', 'vcns-security-automation-manager' ); ?></p></div>
			<?php endif; ?>

			<div class="wp-sam-geoip-header">
				<div class="wp-sam-geoip-header-main">
				<?php if ( $geo_store->token_undecryptable() ) : ?>
					<div class="notice notice-warning inline">
						<p>
							<?php esc_html_e( 'Your saved IPinfo token can no longer be read, usually because this site\'s secret keys have changed. Geo-IP is off until you enter it again.', 'vcns-security-automation-manager' ); ?>
							<button type="button" class="button button-small" data-wp-sam-dialog-open="wp-sam-geoip-settings"><?php esc_html_e( 'Enter token', 'vcns-security-automation-manager' ); ?></button>
						</p>
					</div>
				<?php elseif ( ! $geo_configured ) : ?>
					<div class="notice notice-warning inline">
						<p>
							<?php esc_html_e( 'Geo-IP is off, so the Country Block List below has no effect and can\'t check that a block won\'t lock you out. It needs a token from your own IPinfo account.', 'vcns-security-automation-manager' ); ?>
							<button type="button" class="button button-small" data-wp-sam-dialog-open="wp-sam-geoip-settings"><?php esc_html_e( 'Add token', 'vcns-security-automation-manager' ); ?></button>
						</p>
					</div>
				<?php else : ?>
					<form method="get" class="wp-sam-inline-form">
						<input type="hidden" name="page" value="security-automation-manager-traffic" />
						<input type="hidden" name="tab" value="network-intelligence" />
						<input type="hidden" name="subtab" value="geoip" />
						<span class="wp-sam-geoip-status"><?php esc_html_e( 'Geo-IP is on, using your IPinfo token.', 'vcns-security-automation-manager' ); ?></span>
						<label for="geo_lookup_ip"><?php esc_html_e( 'Look up an IP:', 'vcns-security-automation-manager' ); ?></label>
						<input type="text" id="geo_lookup_ip" name="geo_lookup_ip" placeholder="203.0.113.42" value="<?php echo esc_attr( isset( $_GET['geo_lookup_ip'] ) ? sanitize_text_field( wp_unslash( $_GET['geo_lookup_ip'] ) ) : '' ); // phpcs:ignore WordPress.Security.NonceVerification.Recommended ?>" style="width:220px" />
						<?php submit_button( __( 'Look Up', 'vcns-security-automation-manager' ), 'secondary', '', false ); ?>
					</form>
				<?php endif; ?>
				</div>
				<button type="button" class="button wp-sam-settings-cog" data-wp-sam-dialog-open="wp-sam-geoip-settings" aria-haspopup="dialog" title="<?php esc_attr_e( 'Geo-IP settings', 'vcns-security-automation-manager' ); ?>">
					<span class="dashicons dashicons-admin-generic" aria-hidden="true"></span>
					<span class="screen-reader-text"><?php esc_html_e( 'Geo-IP settings', 'vcns-security-automation-manager' ); ?></span>
				</button>
			</div>

			<?php
			$geo_lookup_ip = isset( $_GET['geo_lookup_ip'] ) ? sanitize_text_field( wp_unslash( $_GET['geo_lookup_ip'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Recommended
			if ( $geo_configured && '' !== $geo_lookup_ip ) :
				$geo_result       = $geo_store->resolve( $geo_lookup_ip );
				$geo_country_code = strtoupper( (string) ( $geo_result['country'] ?? '' ) );
				?>
			<div class="wp-sam-table-wrap">
			<table class="widefat striped wp-sam-table wp-sam-geoip-result-table" style="margin-top:1em">
				<thead>
					<tr>
						<th class="wp-sam-col-technical"><?php esc_html_e( 'IP', 'vcns-security-automation-manager' ); ?></th>
						<th class="wp-sam-col-primary"><?php esc_html_e( 'Country', 'vcns-security-automation-manager' ); ?></th>
						<th class="wp-sam-col-primary"><?php esc_html_e( 'Region', 'vcns-security-automation-manager' ); ?></th>
						<th class="wp-sam-col-primary"><?php esc_html_e( 'City', 'vcns-security-automation-manager' ); ?></th>
					</tr>
				</thead>
				<tbody>
					<tr>
						<td class="wp-sam-col-technical"><code><?php echo esc_html( $geo_lookup_ip ); ?></code></td>
						<td class="wp-sam-col-primary">
							<?php
							echo esc_html(
								'' !== $geo_country_code
									/* translators: 1: country name, 2: two-letter country code */
									? sprintf( __( '%1$s (%2$s)', 'vcns-security-automation-manager' ), $geoip_country_names[ $geo_country_code ] ?? $geo_country_code, $geo_country_code )
									: __( 'Not found', 'vcns-security-automation-manager' )
							);
							?>
						</td>
						<td class="wp-sam-col-primary"><?php echo esc_html( $geo_result['region'] ?? '—' ); ?></td>
						<td class="wp-sam-col-primary"><?php echo esc_html( $geo_result['city'] ?? '—' ); ?></td>
					</tr>
				</tbody>
			</table>
			</div>
			<?php endif; ?>

			<?php
			// Deliberately never deleted here: this is a GET render, and an
			// admin can easily re-view this page without acting on the
			// warning yet (a refresh, a second tab, following the
			// warning's own advice to check the IP Rules tab first and
			// coming back) -- clearing it on every such incidental view
			// would silently discard the warning and the pending selection
			// before the admin ever got to confirm or reconsider it. The
			// 5-minute TTL set when this was written is what actually
			// expires it; the only explicit delete_transient() for this key
			// is handle_geoip_country_block_save()'s own successful save.
			$geoip_lockout_pending = get_transient( Admin_UI::GEOIP_LOCKOUT_TRANSIENT_PREFIX . get_current_user_id() );
			$geoip_confirming      = is_array( $geoip_lockout_pending );

			$geoip_country_rules = array_filter(
				( new Network_Rule_Store() )->all(),
				static fn( $rule ) => 'country' === $rule['rule_type'] && '' === (string) $rule['surface']
			);
			$geoip_blocked_codes = array_map( static fn( $rule ) => (string) $rule['value'], $geoip_country_rules );
			$geoip_checked_codes = $geoip_confirming ? (array) $geoip_lockout_pending['countries'] : $geoip_blocked_codes;
			?>

			<h3 id="wp-sam-country-block-list" style="margin:1.5em 0 0.25em"><?php esc_html_e( 'Country Block List', 'vcns-security-automation-manager' ); ?></h3>
			<p class="description" style="margin-top:0">
				<?php esc_html_e( 'Every country is allowed until you tick it. Nothing changes until you click Save.', 'vcns-security-automation-manager' ); ?>
			</p>

			<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" style="margin-top:0.75em">
				<?php wp_nonce_field( 'wp_sam_geoip_country_block_save' ); ?>
				<input type="hidden" name="action" value="wp_sam_geoip_country_block_save" />
				<?php if ( $geoip_confirming ) : ?>
				<div class="notice notice-warning inline" style="padding:12px 16px;margin-bottom:1em">
					<p style="margin-top:0"><strong><?php esc_html_e( 'This could lock you out of wp-admin:', 'vcns-security-automation-manager' ); ?></strong> <?php echo esc_html( (string) $geoip_lockout_pending['message'] ); ?></p>
					<p>
						<label>
							<input type="checkbox" name="confirm_lockout_risk" value="1" />
							<?php esc_html_e( 'I understand this may lock me out of wp-admin -- save anyway.', 'vcns-security-automation-manager' ); ?>
						</label>
					</p>
				</div>
				<?php endif; ?>
				<?php
				// Selection aid only: the group <select> has no name, so it is
				// never posted -- assets/js/admin.js just ticks/unticks the
				// grid's own checkboxes, and blocked_countries[] stays the only
				// thing handle_geoip_country_block_save() ever sees.
				$geoip_ticked_count     = count( array_intersect( array_keys( $geoip_country_names ), $geoip_checked_codes ) );
				$geoip_group_categories = Country_Groups::by_category( $geoip_site_country );
				?>
				<div class="wp-sam-country-groups" id="wp-sam-country-groups">
					<div class="wp-sam-inline-form">
						<label for="wp-sam-country-group-select"><strong><?php esc_html_e( 'Select by group', 'vcns-security-automation-manager' ); ?></strong></label>
						<select id="wp-sam-country-group-select" aria-describedby="wp-sam-country-group-help wp-sam-country-group-details">
							<option value=""><?php esc_html_e( '— Choose a group —', 'vcns-security-automation-manager' ); ?></option>
							<?php foreach ( $geoip_group_categories as $geoip_category ) : ?>
							<optgroup label="<?php echo esc_attr( $geoip_category['label'] ); ?>">
								<?php foreach ( $geoip_category['groups'] as $geoip_group_key => $geoip_group ) : ?>
								<option value="<?php echo esc_attr( $geoip_group_key ); ?>" data-codes="<?php echo esc_attr( implode( ' ', $geoip_group['codes'] ) ); ?>">
									<?php
									/* translators: 1: group name, e.g. "Northern Europe"; 2: number of countries in it. */
									echo esc_html( sprintf( __( '%1$s (%2$d)', 'vcns-security-automation-manager' ), $geoip_group['label'], count( $geoip_group['codes'] ) ) );
									?>
								</option>
								<?php endforeach; ?>
							</optgroup>
							<?php endforeach; ?>
						</select>
						<button type="button" class="button" data-wp-sam-country-group-action="tick" disabled><?php esc_html_e( 'Tick all in group', 'vcns-security-automation-manager' ); ?></button>
						<button type="button" class="button" data-wp-sam-country-group-action="untick" disabled><?php esc_html_e( 'Untick all in group', 'vcns-security-automation-manager' ); ?></button>
						<span class="wp-sam-country-count">
							<?php esc_html_e( 'Countries ticked:', 'vcns-security-automation-manager' ); ?>
							<strong id="wp-sam-country-count" aria-live="polite"><?php echo esc_html( (string) $geoip_ticked_count ); ?></strong>
						</span>
					</div>
					<p class="description" id="wp-sam-country-group-help">
						<?php esc_html_e( 'Ticks or unticks a whole group in the list below. Group lists are bundled with SAM as a snapshot (each shows its source and as-of date) and are never updated automatically.', 'vcns-security-automation-manager' ); ?>
						<?php if ( '' !== $geoip_site_country ) : ?>
							<?php
							/* translators: %s: country name, e.g. "France". */
							echo esc_html( sprintf( __( 'Sanctions lists are narrowed to those that bind in %s.', 'vcns-security-automation-manager' ), $geoip_country_names[ $geoip_site_country ] ) );
							?>
						<button type="button" class="button-link" data-wp-sam-dialog-open="wp-sam-geoip-settings"><?php esc_html_e( 'Change where this website operates', 'vcns-security-automation-manager' ); ?></button>
						<?php else : ?>
						<button type="button" class="button-link" data-wp-sam-dialog-open="wp-sam-geoip-settings"><?php esc_html_e( 'Show only the sanctions lists that apply where this website operates', 'vcns-security-automation-manager' ); ?></button>
						<?php endif; ?>
					</p>

					<div id="wp-sam-country-group-details" class="wp-sam-country-group-details" aria-live="polite">
						<?php foreach ( $geoip_group_categories as $geoip_category_key => $geoip_category ) : ?>
							<?php foreach ( $geoip_category['groups'] as $geoip_group_key => $geoip_group ) : ?>
						<div data-wp-sam-country-group-details="<?php echo esc_attr( $geoip_group_key ); ?>" hidden>
							<p>
								<strong><?php echo esc_html( $geoip_group['label'] ); ?></strong>
								&middot;
								<?php
								/* translators: %s: date the group list was last checked, YYYY-MM-DD. */
								echo esc_html( sprintf( __( 'As of %s', 'vcns-security-automation-manager' ), $geoip_group['as_of'] ) );
								?>
								&middot;
								<?php esc_html_e( 'Source:', 'vcns-security-automation-manager' ); ?>
								<a href="<?php echo esc_url( $geoip_group['source_url'] ); ?>" target="_blank" rel="noopener noreferrer"><?php echo esc_html( $geoip_group['source'] ); ?></a>
							</p>
								<?php if ( '' !== $geoip_group['note'] ) : ?>
							<p><?php echo esc_html( $geoip_group['note'] ); ?></p>
							<?php endif; ?>
								<?php if ( 'sanctions' === $geoip_category_key ) : ?>
							<p><em><?php esc_html_e( 'This is a snapshot taken on the as-of date and SAM does not update it automatically -- check the source for the current list. Sanctions regimes target named persons, entities and sectors; being on this list is not in itself a requirement to block all traffic from a country. Whether to block is your decision.', 'vcns-security-automation-manager' ); ?></em></p>
							<?php endif; ?>
							<p>
								<?php
								echo esc_html(
									implode(
										', ',
										array_map(
											static fn( $geoip_code ) => ( $geoip_country_names[ $geoip_code ] ?? $geoip_code ) . ' (' . $geoip_code . ')',
											$geoip_group['codes']
										)
									)
								);
								?>
							</p>
						</div>
							<?php endforeach; ?>
						<?php endforeach; ?>
					</div>
				</div>
				<div class="wp-sam-country-grid" id="wp-sam-country-grid">
					<?php foreach ( $geoip_country_names as $code => $name ) : ?>
					<label>
						<input type="checkbox" name="blocked_countries[]" value="<?php echo esc_attr( $code ); ?>" <?php checked( in_array( $code, $geoip_checked_codes, true ) ); ?> />
						<?php echo esc_html( $name ); ?> <code><?php echo esc_html( $code ); ?></code>
					</label>
					<?php endforeach; ?>
				</div>
				<?php submit_button( __( 'Save Country Block List', 'vcns-security-automation-manager' ) ); ?>
			</form>

			<?php // Opened by the cog and the buttons above; see assets/js/admin.js. ?>
			<dialog id="wp-sam-geoip-settings" class="wp-sam-dialog" aria-labelledby="wp-sam-geoip-settings-title">
				<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
					<?php wp_nonce_field( 'wp_sam_geoip_settings_save' ); ?>
					<input type="hidden" name="action" value="wp_sam_geoip_settings_save" />
					<h2 id="wp-sam-geoip-settings-title"><?php esc_html_e( 'Geo-IP settings', 'vcns-security-automation-manager' ); ?></h2>

					<p>
						<label for="ipinfo_token"><strong><?php esc_html_e( 'IPinfo API token', 'vcns-security-automation-manager' ); ?></strong></label><br />
						<input type="password" id="ipinfo_token" name="ipinfo_token" autocomplete="off" class="regular-text" aria-describedby="wp-sam-ipinfo-token-help" placeholder="<?php echo $geo_configured ? esc_attr__( 'Saved -- leave blank to keep', 'vcns-security-automation-manager' ) : ''; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- esc_attr__() already escapes. ?>" />
					</p>
					<p class="description" id="wp-sam-ipinfo-token-help">
						<?php esc_html_e( 'From your own IPinfo account -- SAM never uses a shared one.', 'vcns-security-automation-manager' ); ?>
						<?php if ( ! $geo_configured ) : ?>
							<?php esc_html_e( 'Geo-IP stays off until you add one.', 'vcns-security-automation-manager' ); ?>
						<a href="https://ipinfo.io/signup" target="_blank" rel="noopener noreferrer"><?php esc_html_e( 'Sign up free at ipinfo.io', 'vcns-security-automation-manager' ); ?></a>
						<?php endif; ?>
					</p>

					<p>
						<label for="wp-sam-site-country-select"><strong><?php esc_html_e( 'Where does this website operate?', 'vcns-security-automation-manager' ); ?></strong></label><br />
						<select id="wp-sam-site-country-select" name="site_country" aria-describedby="wp-sam-site-country-help">
							<option value=""><?php esc_html_e( '— Not chosen: offer every sanctions list —', 'vcns-security-automation-manager' ); ?></option>
							<?php foreach ( $geoip_country_names as $code => $name ) : ?>
							<option value="<?php echo esc_attr( $code ); ?>"<?php selected( $geoip_site_country, $code ); ?>><?php echo esc_html( $name ); ?></option>
							<?php endforeach; ?>
						</select>
					</p>
					<p class="description" id="wp-sam-site-country-help">
						<?php esc_html_e( 'Narrows the sanctions lists offered under "Select by group" to the UN list and the lists that bind in that country -- the EU\'s for France, the UK\'s for Jersey. It never blocks anything itself. Sanctions also follow people and companies, not only places: a site run by a US company, or by a UK national living abroad, may be bound by their own country\'s lists as well, so leave this unchosen to see every list.', 'vcns-security-automation-manager' ); ?>
					</p>

					<div class="wp-sam-dialog-actions">
						<?php if ( $geo_configured ) : ?>
						<button type="submit" form="wp-sam-geoip-remove-token" class="button-link button-link-delete"><?php esc_html_e( 'Remove token and turn Geo-IP off', 'vcns-security-automation-manager' ); ?></button>
						<?php endif; ?>
						<button type="button" class="button" data-wp-sam-dialog-close><?php esc_html_e( 'Cancel', 'vcns-security-automation-manager' ); ?></button>
						<button type="submit" class="button button-primary"><?php esc_html_e( 'Save', 'vcns-security-automation-manager' ); ?></button>
					</div>
				</form>
				<?php
				// Its own form, so pressing Enter in the token field can only
				// ever press Save: a form's implicit submission uses its first
				// submit button, and this one belongs to a different form.
				?>
				<?php if ( $geo_configured ) : ?>
				<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" id="wp-sam-geoip-remove-token">
					<?php wp_nonce_field( 'wp_sam_geoip_settings_save' ); ?>
					<input type="hidden" name="action" value="wp_sam_geoip_settings_save" />
					<input type="hidden" name="remove_token" value="1" />
				</form>
				<?php endif; ?>
			</dialog>

		<?php elseif ( 'well-known' === $ni_subtab ) : ?>

			<?php $well_known_key = isset( $_GET['file'] ) ? sanitize_key( wp_unslash( $_GET['file'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Recommended ?>

			<?php if ( Well_Known_File_Catalog::has( $well_known_key ) ) : ?>

				<?php require __DIR__ . '/partials/well-known-file-editor.php'; ?>

			<?php else : ?>

				<?php
				$robots_rules_store   = new Robots_Rules_Store();
				$agents_rules_store   = new Agents_Rules_Store();
				$security_txt_store   = new Security_Txt_Store();
				$humans_txt_store     = new Humans_Txt_Store();
				$ads_txt_store        = new Ads_Txt_Store();
				$app_ads_txt_store    = new App_Ads_Txt_Store();
				$security_txt_expires = $security_txt_store->fields()['Expires'][0] ?? null;
				$robots_rule_count    = count( $robots_rules_store->rules() );
				$agents_rule_count    = count( $agents_rules_store->rules() );
				$ads_record_count     = count( $ads_txt_store->records() );
				$app_ads_record_count = count( $app_ads_txt_store->records() );

				if ( ! $security_txt_store->is_present() ) {
					$security_txt_contents = __( 'Not present', 'vcns-security-automation-manager' );
				} elseif ( null === $security_txt_expires ) {
					$security_txt_contents = __( 'Present', 'vcns-security-automation-manager' );
				} else {
					/* translators: %s: the date in the file's Expires field */
					$security_txt_contents = sprintf( __( 'Present, expires %s', 'vcns-security-automation-manager' ), $security_txt_expires );
				}

				// One row per file, in Well_Known_File_Catalog's order.
				$well_known_files = array(
					'robots'   => array(
						/* translators: %s: number of disallow rules */
						'contents'  => sprintf( _n( '%s disallow rule', '%s disallow rules', $robots_rule_count, 'vcns-security-automation-manager' ), number_format( $robots_rule_count ) ),
						'expired'   => false,
						'refreshed' => $robots_rules_store->last_refreshed_at(),
						'status'    => $robots_rules_store->last_fetch_status(),
						'action'    => 'wp_sam_robots_rules_refresh',
					),
					'agents'   => array(
						/* translators: %s: number of disallow rules */
						'contents'  => sprintf( _n( '%s disallow rule', '%s disallow rules', $agents_rule_count, 'vcns-security-automation-manager' ), number_format( $agents_rule_count ) ),
						'expired'   => false,
						'refreshed' => $agents_rules_store->last_refreshed_at(),
						'status'    => $agents_rules_store->last_fetch_status(),
						'action'    => 'wp_sam_agents_rules_refresh',
					),
					'security' => array(
						'contents'  => $security_txt_contents,
						'expired'   => null !== $security_txt_expires && $security_txt_store->is_expired(),
						'refreshed' => $security_txt_store->last_refreshed_at(),
						'status'    => $security_txt_store->last_fetch_status(),
						'action'    => 'wp_sam_security_txt_refresh',
					),
					'humans'   => array(
						'contents'  => $humans_txt_store->is_present() ? __( 'Present', 'vcns-security-automation-manager' ) : __( 'Not present', 'vcns-security-automation-manager' ),
						'expired'   => false,
						'refreshed' => $humans_txt_store->last_refreshed_at(),
						'status'    => $humans_txt_store->last_fetch_status(),
						'action'    => 'wp_sam_humans_txt_refresh',
					),
					'ads'      => array(
						/* translators: %s: number of authorised-seller records */
						'contents'  => sprintf( _n( '%s authorised-seller record', '%s authorised-seller records', $ads_record_count, 'vcns-security-automation-manager' ), number_format( $ads_record_count ) ),
						'expired'   => false,
						'refreshed' => $ads_txt_store->last_refreshed_at(),
						'status'    => $ads_txt_store->last_fetch_status(),
						'action'    => 'wp_sam_ads_txt_refresh',
					),
					'app-ads'  => array(
						/* translators: %s: number of authorised-seller records */
						'contents'  => sprintf( _n( '%s authorised-seller record', '%s authorised-seller records', $app_ads_record_count, 'vcns-security-automation-manager' ), number_format( $app_ads_record_count ) ),
						'expired'   => false,
						'refreshed' => $app_ads_txt_store->last_refreshed_at(),
						'status'    => $app_ads_txt_store->last_fetch_status(),
						'action'    => 'wp_sam_app_ads_txt_refresh',
					),
				);

				$well_known_catalog       = Well_Known_File_Catalog::files();
				$well_known_saved_store   = new Well_Known_File_Store();
				$well_known_served_labels = array(
					Well_Known_File_Store::CHECK_SERVED => __( 'Served by this plugin', 'vcns-security-automation-manager' ),
					Well_Known_File_Store::CHECK_NOT_SERVED => __( 'Saved here, but visitors get another version', 'vcns-security-automation-manager' ),
					Well_Known_File_Store::CHECK_UNREACHABLE => __( 'Saved here, not yet confirmed', 'vcns-security-automation-manager' ),
				);

				$well_known_removed = isset( $_GET['removed'] ) ? sanitize_key( wp_unslash( $_GET['removed'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- display-only flag set by our own redirect.
				?>

				<?php if ( isset( $well_known_catalog[ $well_known_removed ] ) ) : ?>
				<div class="notice notice-success inline"><p>
					<?php
					/* translators: %s: file name, e.g. Robots.txt */
					echo esc_html( sprintf( __( 'This plugin no longer serves %s. Visitors get whatever the site served before.', 'vcns-security-automation-manager' ), $well_known_catalog[ $well_known_removed ]['label'] ) );
					?>
				</p></div>
				<?php endif; ?>

				<p class="description">
					<?php esc_html_e( 'This plugin reads each file from the site once a day. Robots.txt and agents.txt rules are also used to spot known crawlers ignoring them; nothing here blocks a visitor. Create or Edit opens a guided editor, and this plugin serves what you save there.', 'vcns-security-automation-manager' ); ?>
				</p>

				<div class="wp-sam-table-wrap">
				<table class="widefat striped wp-sam-table wp-sam-well-known-table" style="margin-top:1em">
					<thead>
						<tr>
							<th class="wp-sam-col-primary"><?php esc_html_e( 'File', 'vcns-security-automation-manager' ); ?></th>
							<th class="wp-sam-col-status"><?php esc_html_e( 'Contents', 'vcns-security-automation-manager' ); ?></th>
							<th class="wp-sam-col-datetime"><?php esc_html_e( 'Last refreshed', 'vcns-security-automation-manager' ); ?></th>
							<th class="wp-sam-col-status"><?php esc_html_e( 'Last fetch status', 'vcns-security-automation-manager' ); ?></th>
							<th class="wp-sam-col-actions"><?php esc_html_e( 'Actions', 'vcns-security-automation-manager' ); ?></th>
						</tr>
					</thead>
					<tbody>
					<?php foreach ( $well_known_files as $well_known_file_key => $well_known_file ) : ?>
						<?php $well_known_saved = $well_known_saved_store->get( $well_known_file_key ); ?>
						<tr>
							<td class="wp-sam-col-primary"><?php echo esc_html( $well_known_catalog[ $well_known_file_key ]['label'] ); ?></td>
							<td class="wp-sam-col-status">
								<?php echo esc_html( $well_known_file['contents'] ); ?>
								<?php if ( $well_known_file['expired'] ) : ?>
								<strong style="color:#a94442"><?php esc_html_e( '(expired)', 'vcns-security-automation-manager' ); ?></strong>
								<?php endif; ?>
								<?php if ( null !== $well_known_saved ) : ?>
								<br /><span class="description"><?php echo esc_html( $well_known_served_labels[ $well_known_saved['check'] ] ?? __( 'Saved here', 'vcns-security-automation-manager' ) ); ?></span>
								<?php endif; ?>
							</td>
							<td class="wp-sam-col-datetime"><?php echo esc_html( $well_known_file['refreshed'] ?? __( 'Never', 'vcns-security-automation-manager' ) ); ?></td>
							<td class="wp-sam-col-status"><?php echo esc_html( '' !== $well_known_file['status'] ? ucfirst( $well_known_file['status'] ) : __( 'Not yet run', 'vcns-security-automation-manager' ) ); ?></td>
							<td class="wp-sam-col-actions">
								<a class="button button-small" href="<?php echo esc_url( Admin_UI::well_known_editor_url( $well_known_file_key ) ); ?>"><?php echo esc_html( null === $well_known_saved && 'absent' === $well_known_file['status'] ? __( 'Create', 'vcns-security-automation-manager' ) : __( 'Edit', 'vcns-security-automation-manager' ) ); ?></a>
								<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" style="display:inline">
									<?php wp_nonce_field( $well_known_file['action'] ); ?>
									<input type="hidden" name="action" value="<?php echo esc_attr( $well_known_file['action'] ); ?>" />
									<?php submit_button( __( 'Refresh Now', 'vcns-security-automation-manager' ), 'secondary small', '', false ); ?>
								</form>
							</td>
						</tr>
					<?php endforeach; ?>
					</tbody>
				</table>
				</div>

			<?php endif; ?>

		<?php elseif ( 'network-rules' === $ni_subtab ) : ?>

			<?php
			$network_rules           = ( new Network_Rule_Store() )->all();
			$network_rules_geoip_url = add_query_arg( 'subtab', 'geoip', $ni_base_url ) . '#wp-sam-country-block-list';
			$network_rules_countries = array_filter( $network_rules, static fn( $rule ) => 'country' === $rule['rule_type'] );
			?>

			<p class="description">
				<?php esc_html_e( "Block traffic by ASN or country, checked alongside IP Rules -- an explicit decision, applied regardless of a surface's observe/enforce mode. Adding the first rule here is what switches ASN/Geo-IP resolution on for every request; with no rules configured, nothing here costs anything.", 'vcns-security-automation-manager' ); ?>
			</p>
			<p class="description">
				<?php esc_html_e( 'To block countries on every surface, tick them in the Country Block List instead:', 'vcns-security-automation-manager' ); ?>
				<a href="<?php echo esc_url( $network_rules_geoip_url ); ?>"><?php esc_html_e( 'Geo-IP → Country Block List', 'vcns-security-automation-manager' ); ?></a>.
				<?php esc_html_e( 'Use this page for ASN rules, or to block a country on one surface only.', 'vcns-security-automation-manager' ); ?>
			</p>

			<?php if ( ! empty( $network_rules_countries ) && ! ( new Geo_Ip_Store() )->is_configured() ) : ?>
			<div class="notice notice-warning inline">
				<p>
					<?php esc_html_e( 'The country rules below have no effect while Geo-IP is off: nothing can tell which country a visitor is in.', 'vcns-security-automation-manager' ); ?>
					<a href="<?php echo esc_url( add_query_arg( 'subtab', 'geoip', $ni_base_url ) ); ?>"><?php esc_html_e( 'Turn on Geo-IP', 'vcns-security-automation-manager' ); ?></a>
				</p>
			</div>
			<?php endif; ?>

			<div class="wp-sam-table-wrap">
			<table class="widefat striped wp-sam-table wp-sam-violations-table" style="margin-top:1em">
				<thead>
					<tr>
						<th class="wp-sam-col-status"><?php esc_html_e( 'Type', 'vcns-security-automation-manager' ); ?></th>
						<th class="wp-sam-col-technical"><?php esc_html_e( 'Value', 'vcns-security-automation-manager' ); ?></th>
						<th class="wp-sam-col-surface"><?php esc_html_e( 'Surface', 'vcns-security-automation-manager' ); ?></th>
						<th class="wp-sam-col-description"><?php esc_html_e( 'Reason', 'vcns-security-automation-manager' ); ?></th>
						<th class="wp-sam-col-actions"><?php esc_html_e( 'Actions', 'vcns-security-automation-manager' ); ?></th>
					</tr>
				</thead>
				<tbody>
				<?php foreach ( $network_rules as $network_rule ) : ?>
				<tr>
					<td class="wp-sam-col-status"><?php echo esc_html( 'asn' === $network_rule['rule_type'] ? __( 'ASN', 'vcns-security-automation-manager' ) : __( 'Country', 'vcns-security-automation-manager' ) ); ?></td>
					<td class="wp-sam-col-technical">
						<?php if ( 'asn' === $network_rule['rule_type'] ) : ?>
						<a href="<?php echo esc_url( add_query_arg( 'asn', (string) $network_rule['value'], add_query_arg( 'subtab', 'asn', $ni_base_url ) ) ); ?>"><code><?php echo esc_html( 'AS' . (string) $network_rule['value'] ); ?></code></a>
						<?php else : ?>
						<code><?php echo esc_html( (string) $network_rule['value'] ); ?></code>
						<?php endif; ?>
					</td>
					<td class="wp-sam-col-surface"><?php echo esc_html( '' !== (string) $network_rule['surface'] ? ucfirst( (string) $network_rule['surface'] ) : __( 'All', 'vcns-security-automation-manager' ) ); ?></td>
					<td class="wp-sam-col-description"><?php echo esc_html( (string) $network_rule['reason'] ); ?></td>
					<td class="wp-sam-col-actions">
						<?php if ( 'country' === $network_rule['rule_type'] && '' === (string) $network_rule['surface'] ) : ?>
						<a href="<?php echo esc_url( $network_rules_geoip_url ); ?>" class="button button-small"><?php esc_html_e( 'Change on Geo-IP', 'vcns-security-automation-manager' ); ?></a>
						<?php endif; ?>
						<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" style="display:inline">
							<?php wp_nonce_field( 'wp_sam_network_rule_delete' ); ?>
							<input type="hidden" name="action" value="wp_sam_network_rule_delete" />
							<input type="hidden" name="rule_id" value="<?php echo esc_attr( (string) $network_rule['id'] ); ?>" />
							<?php submit_button( __( 'Delete', 'vcns-security-automation-manager' ), 'link-delete small', '', false ); ?>
						</form>
					</td>
				</tr>
				<?php endforeach; ?>
				<?php if ( empty( $network_rules ) ) : ?>
				<tr>
					<td colspan="5"><p><?php esc_html_e( 'No network rules yet.', 'vcns-security-automation-manager' ); ?></p></td>
				</tr>
				<?php endif; ?>
				</tbody>
			</table>
			</div>

			<h3 id="wp-sam-network-rule-add" style="margin-top:1.5em"><?php esc_html_e( 'Add a network rule', 'vcns-security-automation-manager' ); ?></h3>

			<?php
			// Same "never delete on a GET render" reasoning as the Geo-IP
			// tab's pending-lockout transient (see that block's own
			// comment) -- only handle_network_rule_add()'s own successful
			// add clears this key; the 5-minute TTL handles the rest.
			$network_rule_lockout_pending = get_transient( Admin_UI::NETWORK_RULE_LOCKOUT_TRANSIENT_PREFIX . get_current_user_id() );
			$network_rule_confirming      = is_array( $network_rule_lockout_pending );

			$network_rule_form_defaults = array(
				'rule_type' => 'asn',
				'value'     => '',
				'surface'   => '',
				'reason'    => '',
			);
			if ( $network_rule_confirming ) {
				$network_rule_form_defaults = array_merge( $network_rule_form_defaults, $network_rule_lockout_pending );
			} elseif ( isset( $_GET['rule_value'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- pre-fills the form (e.g. "Block AS…" on ASN Lookup); nothing is saved until it's submitted.
				$network_rule_form_defaults = array(
					'rule_type' => 'country' === sanitize_key( wp_unslash( $_GET['rule_type'] ?? '' ) ) ? 'country' : 'asn', // phpcs:ignore WordPress.Security.NonceVerification.Recommended
					'value'     => sanitize_text_field( wp_unslash( $_GET['rule_value'] ) ), // phpcs:ignore WordPress.Security.NonceVerification.Recommended
					'surface'   => '',
					'reason'    => sanitize_text_field( wp_unslash( $_GET['rule_reason'] ?? '' ) ), // phpcs:ignore WordPress.Security.NonceVerification.Recommended
				);
			}
			?>

			<?php if ( $network_rule_confirming ) : ?>
			<div class="notice notice-warning inline" style="padding:12px 16px;margin:1em 0">
				<p style="margin-top:0"><strong><?php esc_html_e( 'This could lock you out of wp-admin:', 'vcns-security-automation-manager' ); ?></strong> <?php echo esc_html( (string) $network_rule_lockout_pending['message'] ); ?></p>
			</div>
			<?php endif; ?>

			<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
				<?php wp_nonce_field( 'wp_sam_network_rule_add' ); ?>
				<input type="hidden" name="action" value="wp_sam_network_rule_add" />
				<table class="form-table">
					<tr>
						<th><label for="rule_type"><?php esc_html_e( 'Type', 'vcns-security-automation-manager' ); ?></label></th>
						<td>
							<select id="rule_type" name="rule_type">
								<option value="asn" <?php selected( $network_rule_form_defaults['rule_type'], 'asn' ); ?>><?php esc_html_e( 'ASN', 'vcns-security-automation-manager' ); ?></option>
								<option value="country" <?php selected( $network_rule_form_defaults['rule_type'], 'country' ); ?>><?php esc_html_e( 'Country', 'vcns-security-automation-manager' ); ?></option>
							</select>
							<p class="description">
								<?php esc_html_e( 'Blocking a country on every surface?', 'vcns-security-automation-manager' ); ?>
								<a href="<?php echo esc_url( $network_rules_geoip_url ); ?>"><?php esc_html_e( 'Use the Country Block List on the Geo-IP tab', 'vcns-security-automation-manager' ); ?></a>
							</p>
						</td>
					</tr>
					<tr>
						<th><label for="value"><?php esc_html_e( 'Value', 'vcns-security-automation-manager' ); ?></label></th>
						<td>
							<input type="text" id="value" name="value" required placeholder="<?php esc_attr_e( 'AS15169, or a two-letter country code such as CN', 'vcns-security-automation-manager' ); ?>" style="width:100%;max-width:300px" value="<?php echo esc_attr( (string) $network_rule_form_defaults['value'] ); ?>" />
						</td>
					</tr>
					<tr>
						<th><label for="network_rule_surface"><?php esc_html_e( 'Surface', 'vcns-security-automation-manager' ); ?></label></th>
						<td>
							<select id="network_rule_surface" name="surface">
								<option value="" <?php selected( $network_rule_form_defaults['surface'], '' ); ?>><?php esc_html_e( 'All surfaces', 'vcns-security-automation-manager' ); ?></option>
								<?php foreach ( array( 'frontend', 'admin', 'login', 'api' ) as $network_rule_surface ) : ?>
								<option value="<?php echo esc_attr( $network_rule_surface ); ?>" <?php selected( $network_rule_form_defaults['surface'], $network_rule_surface ); ?>><?php echo esc_html( ucfirst( $network_rule_surface ) ); ?></option>
								<?php endforeach; ?>
							</select>
						</td>
					</tr>
					<tr>
						<th><label for="network_rule_reason"><?php esc_html_e( 'Reason', 'vcns-security-automation-manager' ); ?></label></th>
						<td><input type="text" id="network_rule_reason" name="reason" required style="width:100%;max-width:300px" value="<?php echo esc_attr( (string) $network_rule_form_defaults['reason'] ); ?>" /></td>
					</tr>
					<?php if ( $network_rule_confirming ) : ?>
					<tr>
						<th></th>
						<td>
							<label>
								<input type="checkbox" name="confirm_lockout_risk" value="1" />
								<?php esc_html_e( 'I understand this may lock me out of wp-admin -- save anyway.', 'vcns-security-automation-manager' ); ?>
							</label>
						</td>
					</tr>
					<?php endif; ?>
				</table>
				<?php submit_button( __( 'Add rule', 'vcns-security-automation-manager' ) ); ?>
			</form>

		<?php endif; ?>

		</div>

	<?php elseif ( 'detectors' === $tab ) : ?>

		<?php
		$detector_policies = new Detector_Policy_Store();
		$detectors         = Detector_Registry::all();
		usort( $detectors, static fn( $a, $b ) => strcmp( $a->id(), $b->id() ) );
		?>

		<p class="description">
			<?php esc_html_e( 'A detector left on "Observe only" only ever records evidence -- it never contributes to blocking. Switching one to "Enforce" feeds the exact same progressive-response ladder as rate limiting (Warn -> Throttle -> Temporary block -> Extended block), still gated by that surface\'s own Observe/Enforce mode on the Policy tab above. Not every family allows Enforce -- some are reconnaissance signals only, by design.', 'vcns-security-automation-manager' ); ?>
		</p>

		<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" style="margin-top:1em">
			<?php wp_nonce_field( 'wp_sam_detector_policy_update' ); ?>
			<input type="hidden" name="action" value="wp_sam_detector_policy_update" />

			<div class="wp-sam-table-wrap">
			<table class="widefat striped wp-sam-table wp-sam-violations-table wp-sam-detectors-table">
				<thead>
					<tr>
						<th class="wp-sam-col-compact"><?php esc_html_e( 'Detector', 'vcns-security-automation-manager' ); ?></th>
						<th class="wp-sam-col-surface"><?php esc_html_e( 'Family', 'vcns-security-automation-manager' ); ?></th>
						<th class="wp-sam-col-description"><?php esc_html_e( 'Description', 'vcns-security-automation-manager' ); ?></th>
						<th class="wp-sam-col-status"><?php esc_html_e( 'Enabled', 'vcns-security-automation-manager' ); ?></th>
						<th class="wp-sam-col-technical"><?php esc_html_e( 'Control action', 'vcns-security-automation-manager' ); ?></th>
					</tr>
				</thead>
				<tbody>
				<?php foreach ( $detectors as $detector ) : ?>
					<?php
					$allowed      = $detector->allowed_control_actions();
					$effective    = $detector_policies->control_action_for( $detector );
					$field_prefix = 'detector[' . $detector->id() . ']';
					$description  = $detector->description();
					?>
					<tr>
						<td class="wp-sam-col-compact"><code><?php echo esc_html( $detector->id() ); ?></code></td>
						<td class="wp-sam-col-surface"><?php echo esc_html( $detector->family() ); ?></td>
						<td class="wp-sam-col-description"><?php echo '' !== $description ? esc_html( $description ) : '&#8212;'; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- static em-dash literal; $description itself is escaped. ?></td>
						<td class="wp-sam-col-status">
							<input type="checkbox" name="<?php echo esc_attr( $field_prefix ); ?>[enabled]" value="1" <?php checked( $detector_policies->is_enabled( $detector->id() ) ); ?> />
						</td>
						<td class="wp-sam-col-technical">
							<?php if ( count( $allowed ) > 1 ) : ?>
							<select name="<?php echo esc_attr( $field_prefix ); ?>[control_action]">
								<?php foreach ( $allowed as $action ) : ?>
								<option value="<?php echo esc_attr( $action ); ?>" <?php selected( $effective, $action ); ?>>
									<?php echo esc_html( 'enforce' === $action ? __( 'Enforce (feeds progressive blocking)', 'vcns-security-automation-manager' ) : __( 'Observe only', 'vcns-security-automation-manager' ) ); ?>
								</option>
								<?php endforeach; ?>
							</select>
							<?php else : ?>
							<input type="hidden" name="<?php echo esc_attr( $field_prefix ); ?>[control_action]" value="observe" />
								<?php esc_html_e( 'Observe only', 'vcns-security-automation-manager' ); ?>
								<span class="wp-sam-meta-icon" tabindex="0"><span class="dashicons dashicons-info-outline" aria-hidden="true"></span>
									<span class="wp-sam-meta-popover" role="tooltip">
										<?php esc_html_e( 'Fixed -- this family has no Enforce mode. Either it\'s a benign identity/recognition signal (e.g. Tor exit status, a crawler checking robots.txt) rather than an attack pattern, or being flagged alone isn\'t reliable enough on its own to safely block on.', 'vcns-security-automation-manager' ); ?>
									</span>
								</span>
							<?php endif; ?>
						</td>
					</tr>
				<?php endforeach; ?>
				<?php if ( empty( $detectors ) ) : ?>
					<tr>
						<td colspan="5"><p><?php esc_html_e( 'No detectors registered.', 'vcns-security-automation-manager' ); ?></p></td>
					</tr>
				<?php endif; ?>
				</tbody>
			</table>
			</div>

			<?php if ( ! empty( $detectors ) ) : ?>
			<p><?php submit_button( __( 'Save Detector Settings', 'vcns-security-automation-manager' ), 'primary', '', false ); ?></p>
			<?php endif; ?>
		</form>

	<?php elseif ( 'custom-rules' === $tab ) : ?>

		<?php
		$custom_rule_store = new Custom_Rule_Store();
		$custom_rules      = $custom_rule_store->all();

		$edit_id = isset( $_GET['edit'] ) ? absint( $_GET['edit'] ) : 0; // phpcs:ignore WordPress.Security.NonceVerification.Recommended
		$editing = $edit_id > 0 ? $custom_rule_store->get( $edit_id ) : null;

		$errors      = get_transient( 'wp_sam_custom_rule_errors_' . get_current_user_id() );
		$errors      = is_array( $errors ) ? $errors : array();
		$prior_input = get_transient( 'wp_sam_custom_rule_input_' . get_current_user_id() );
		$prior_input = is_array( $prior_input ) ? $prior_input : array();
		delete_transient( 'wp_sam_custom_rule_errors_' . get_current_user_id() );
		delete_transient( 'wp_sam_custom_rule_input_' . get_current_user_id() );

		// Form defaults: a resubmission after a validation error wins (so the
		// admin doesn't lose what they typed), then the rule being edited,
		// then plain empty-form defaults.
		$form_values = array_merge(
			array(
				'name'          => '',
				'pattern'       => '',
				'subject_field' => 'request_uri',
				'severity'      => 'medium',
				'surfaces'      => array(),
				'description'   => '',
			),
			null !== $editing ? array(
				'name'          => $editing['name'],
				'pattern'       => $editing['pattern'],
				'subject_field' => $editing['subject_field'],
				'severity'      => $editing['severity'],
				'surfaces'      => is_array( json_decode( (string) $editing['surfaces'], true ) ) ? json_decode( (string) $editing['surfaces'], true ) : array(),
				'description'   => $editing['description'],
			) : array(),
			$prior_input
		);

		$subject_field_labels = array(
			'request_uri'  => __( 'Request URI (path + query string)', 'vcns-security-automation-manager' ),
			'path'         => __( 'Path only', 'vcns-security-automation-manager' ),
			'query_string' => __( 'Query string only', 'vcns-security-automation-manager' ),
			'user_agent'   => __( 'User-Agent header', 'vcns-security-automation-manager' ),
		);
		$severity_labels      = array(
			'low'      => __( 'Low', 'vcns-security-automation-manager' ),
			'medium'   => __( 'Medium', 'vcns-security-automation-manager' ),
			'high'     => __( 'High', 'vcns-security-automation-manager' ),
			'critical' => __( 'Critical', 'vcns-security-automation-manager' ),
		);
		?>

		<p class="description">
			<?php esc_html_e( 'A custom rule is a plain PHP regular expression (with delimiters, e.g. "/wp-config\.bak$/i") matched against one field of every incoming request. A match is recorded as evidence -- like any built-in detector family, it starts in Observe-only mode; switch it to Enforce on the Detectors tab once you trust it. Saving a rule with an invalid pattern is rejected outright, so a typo fails loudly rather than silently matching nothing.', 'vcns-security-automation-manager' ); ?>
		</p>

		<?php if ( ! empty( $errors ) ) : ?>
		<div class="notice notice-error inline" style="padding:12px 16px;margin:1em 0;">
			<p style="margin-top:0"><strong><?php esc_html_e( 'Rule not saved:', 'vcns-security-automation-manager' ); ?></strong></p>
			<ul style="margin-bottom:0;list-style:disc;padding-left:1.5em">
				<?php foreach ( $errors as $error ) : ?>
				<li><?php echo esc_html( $error ); ?></li>
				<?php endforeach; ?>
			</ul>
		</div>
		<?php endif; ?>

		<div class="wp-sam-table-wrap">
		<table class="widefat striped wp-sam-table wp-sam-violations-table" style="margin-top:1em">
			<thead>
				<tr>
					<th class="wp-sam-col-primary"><?php esc_html_e( 'Name', 'vcns-security-automation-manager' ); ?></th>
					<th class="wp-sam-col-technical"><?php esc_html_e( 'Pattern', 'vcns-security-automation-manager' ); ?></th>
					<th class="wp-sam-col-technical"><?php esc_html_e( 'Matches against', 'vcns-security-automation-manager' ); ?></th>
					<th class="wp-sam-col-status"><?php esc_html_e( 'Severity', 'vcns-security-automation-manager' ); ?></th>
					<th class="wp-sam-col-surface"><?php esc_html_e( 'Surfaces', 'vcns-security-automation-manager' ); ?></th>
					<th class="wp-sam-col-actions"><?php esc_html_e( 'Actions', 'vcns-security-automation-manager' ); ?></th>
				</tr>
			</thead>
			<tbody>
			<?php foreach ( $custom_rules as $rule ) : ?>
				<?php $rule_surfaces = json_decode( (string) $rule['surfaces'], true ); ?>
				<tr>
					<td class="wp-sam-col-primary"><?php echo esc_html( (string) $rule['name'] ); ?></td>
					<td class="wp-sam-col-technical"><code><?php echo esc_html( (string) $rule['pattern'] ); ?></code></td>
					<td class="wp-sam-col-technical"><?php echo esc_html( $subject_field_labels[ $rule['subject_field'] ] ?? (string) $rule['subject_field'] ); ?></td>
					<td class="wp-sam-col-status"><?php echo esc_html( $severity_labels[ $rule['severity'] ] ?? (string) $rule['severity'] ); ?></td>
					<td class="wp-sam-col-surface"><?php echo esc_html( ! empty( $rule_surfaces ) ? implode( ', ', array_map( 'ucfirst', $rule_surfaces ) ) : __( 'All', 'vcns-security-automation-manager' ) ); ?></td>
					<td class="wp-sam-col-actions" style="white-space:nowrap">
						<a href="
						<?php
						echo esc_url(
							add_query_arg(
								array(
									'tab'  => 'custom-rules',
									'edit' => $rule['id'],
								),
								$base_url
							) . '#wp-sam-custom-rule-form'
						);
						?>
									"><?php esc_html_e( 'Edit', 'vcns-security-automation-manager' ); ?></a>
						&nbsp;|&nbsp;
						<code><?php echo esc_html( ( new Custom_Rule_Detector( $rule ) )->id() ); ?></code>
						<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" style="display:inline">
							<?php wp_nonce_field( 'wp_sam_custom_rule_delete' ); ?>
							<input type="hidden" name="action" value="wp_sam_custom_rule_delete" />
							<input type="hidden" name="rule_id" value="<?php echo esc_attr( (string) $rule['id'] ); ?>" />
							<?php submit_button( __( 'Delete', 'vcns-security-automation-manager' ), 'link-delete small', '', false ); ?>
						</form>
					</td>
				</tr>
			<?php endforeach; ?>
			<?php if ( empty( $custom_rules ) ) : ?>
				<tr>
					<td colspan="6"><p><?php esc_html_e( 'No custom rules yet.', 'vcns-security-automation-manager' ); ?></p></td>
				</tr>
			<?php endif; ?>
			</tbody>
		</table>
		</div>
		<p class="description">
			<?php esc_html_e( 'A rule\'s detector id (shown next to Delete above, e.g. "custom_3") is how it appears on the Detectors tab -- use it to find the right row there once you\'ve created a rule.', 'vcns-security-automation-manager' ); ?>
		</p>

		<h2 id="wp-sam-custom-rule-form" style="margin-top:2em">
			<?php echo null !== $editing ? esc_html__( 'Edit rule', 'vcns-security-automation-manager' ) : esc_html__( 'Add a rule', 'vcns-security-automation-manager' ); ?>
		</h2>
		<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
			<?php wp_nonce_field( 'wp_sam_custom_rule_save' ); ?>
			<input type="hidden" name="action" value="wp_sam_custom_rule_save" />
			<?php if ( null !== $editing ) : ?>
			<input type="hidden" name="rule_id" value="<?php echo esc_attr( (string) $editing['id'] ); ?>" />
			<?php endif; ?>
			<table class="form-table">
				<tr>
					<th><label for="wp_sam_cr_name"><?php esc_html_e( 'Name', 'vcns-security-automation-manager' ); ?></label></th>
					<td><input type="text" id="wp_sam_cr_name" name="name" required maxlength="128" style="width:100%;max-width:400px" value="<?php echo esc_attr( (string) $form_values['name'] ); ?>" /></td>
				</tr>
				<tr>
					<th><label for="wp_sam_cr_pattern"><?php esc_html_e( 'Pattern', 'vcns-security-automation-manager' ); ?></label></th>
					<td>
						<input type="text" id="wp_sam_cr_pattern" name="pattern" required maxlength="500" style="width:100%;max-width:500px;font-family:monospace" placeholder="/wp-config\.bak$/i" value="<?php echo esc_attr( (string) $form_values['pattern'] ); ?>" />
						<p class="description"><?php esc_html_e( 'A PHP-style regular expression, including its delimiters and any flags (e.g. /pattern/i).', 'vcns-security-automation-manager' ); ?></p>
					</td>
				</tr>
				<tr>
					<th><label for="wp_sam_cr_subject_field"><?php esc_html_e( 'Matches against', 'vcns-security-automation-manager' ); ?></label></th>
					<td>
						<select id="wp_sam_cr_subject_field" name="subject_field">
							<?php foreach ( $subject_field_labels as $value => $label ) : ?>
							<option value="<?php echo esc_attr( $value ); ?>" <?php selected( $form_values['subject_field'], $value ); ?>><?php echo esc_html( $label ); ?></option>
							<?php endforeach; ?>
						</select>
					</td>
				</tr>
				<tr>
					<th><label for="wp_sam_cr_severity"><?php esc_html_e( 'Severity', 'vcns-security-automation-manager' ); ?></label></th>
					<td>
						<select id="wp_sam_cr_severity" name="severity">
							<?php foreach ( $severity_labels as $value => $label ) : ?>
							<option value="<?php echo esc_attr( $value ); ?>" <?php selected( $form_values['severity'], $value ); ?>><?php echo esc_html( $label ); ?></option>
							<?php endforeach; ?>
						</select>
					</td>
				</tr>
				<tr>
					<th><?php esc_html_e( 'Surfaces', 'vcns-security-automation-manager' ); ?></th>
					<td>
						<?php foreach ( array( 'frontend', 'admin', 'login', 'api' ) as $s ) : ?>
						<label style="margin-right:1em">
							<input type="checkbox" name="surfaces[]" value="<?php echo esc_attr( $s ); ?>" <?php checked( in_array( $s, (array) $form_values['surfaces'], true ) ); ?> />
							<?php echo esc_html( ucfirst( $s ) ); ?>
						</label>
						<?php endforeach; ?>
						<p class="description"><?php esc_html_e( 'Leave every box unchecked to apply this rule to every surface.', 'vcns-security-automation-manager' ); ?></p>
					</td>
				</tr>
				<tr>
					<th><label for="wp_sam_cr_description"><?php esc_html_e( 'Description', 'vcns-security-automation-manager' ); ?></label></th>
					<td><textarea id="wp_sam_cr_description" name="description" rows="2" style="width:100%;max-width:500px"><?php echo esc_textarea( (string) $form_values['description'] ); ?></textarea></td>
				</tr>
			</table>
			<?php submit_button( null !== $editing ? __( 'Save changes', 'vcns-security-automation-manager' ) : __( 'Add rule', 'vcns-security-automation-manager' ) ); ?>
			<?php if ( null !== $editing ) : ?>
			<a href="<?php echo esc_url( add_query_arg( 'tab', 'custom-rules', $base_url ) ); ?>" class="button"><?php esc_html_e( 'Cancel', 'vcns-security-automation-manager' ); ?></a>
			<?php endif; ?>
		</form>

		<h2 style="margin-top:2em"><?php esc_html_e( 'Test a pattern', 'vcns-security-automation-manager' ); ?></h2>
		<p class="description"><?php esc_html_e( 'Paste a pattern and a sample value (e.g. a real request path you\'ve seen in your logs) to check whether it matches, without saving anything.', 'vcns-security-automation-manager' ); ?></p>
		<table class="form-table">
			<tr>
				<th><label for="wp_sam_cr_test_pattern"><?php esc_html_e( 'Pattern', 'vcns-security-automation-manager' ); ?></label></th>
				<td><input type="text" id="wp_sam_cr_test_pattern" style="width:100%;max-width:500px;font-family:monospace" placeholder="/wp-config\.bak$/i" /></td>
			</tr>
			<tr>
				<th><label for="wp_sam_cr_test_sample"><?php esc_html_e( 'Sample value', 'vcns-security-automation-manager' ); ?></label></th>
				<td><input type="text" id="wp_sam_cr_test_sample" style="width:100%;max-width:500px;font-family:monospace" placeholder="/old-backups/wp-config.bak" /></td>
			</tr>
		</table>
		<p>
			<button type="button" class="button" id="wp-sam-custom-rule-test-button"><?php esc_html_e( 'Test', 'vcns-security-automation-manager' ); ?></button>
			<span id="wp-sam-custom-rule-test-result" role="status" style="margin-left:1em;font-weight:600"></span>
		</p>

	<?php endif; ?>
</div>
