<?php
/**
 * Admin view: Traffic Controls (Phase 3E, .roadmap/phase3_early_plan.md §13).
 * This plugin's first active request-blocking capability -- see
 * Intelligence\Traffic_Guard's docblock for the default-safety design
 * (every surface starts in 'observe' mode; nothing blocks until an
 * administrator explicitly promotes a surface to 'enforce').
 *
 * Three tabs: Policy (per-surface mode + thresholds), IP Rules (manual
 * allow/block list), Blocks (live view of automatic progressive-response
 * state, with Release/Make Persistent admin actions).
 *
 * Rendered by Admin_UI::render_traffic().
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use WP_SAM\Intelligence\Ads_Txt_Store;
use WP_SAM\Intelligence\Agents_Rules_Store;
use WP_SAM\Intelligence\App_Ads_Txt_Store;
use WP_SAM\Intelligence\Asn_Lookup_Store;
use WP_SAM\Intelligence\Custom_Rule_Store;
use WP_SAM\Intelligence\Detector_Policy_Store;
use WP_SAM\Intelligence\Detector_Registry;
use WP_SAM\Intelligence\Detectors\Custom_Rule_Detector;
use WP_SAM\Intelligence\Geo_Ip_Store;
use WP_SAM\Intelligence\Humans_Txt_Store;
use WP_SAM\Intelligence\Ip_Rule_Store;
use WP_SAM\Intelligence\Iso_Countries;
use WP_SAM\Intelligence\Network_Rule_Store;
use WP_SAM\Intelligence\Robots_Rules_Store;
use WP_SAM\Intelligence\Security_Txt_Store;
use WP_SAM\Intelligence\Tor_Exit_List_Store;
use WP_SAM\Intelligence\Traffic_Block_Store;
use WP_SAM\Intelligence\Traffic_Policy_Store;

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

		<table class="widefat fixed striped wp-sam-policy-table" style="margin-top:1em">
			<thead>
				<tr>
					<th><?php esc_html_e( 'Surface', 'vcns-security-automation-manager' ); ?></th>
					<th><?php esc_html_e( 'Mode', 'vcns-security-automation-manager' ); ?></th>
					<th><?php esc_html_e( 'Rate limit', 'vcns-security-automation-manager' ); ?></th>
					<th><?php esc_html_e( 'Failed login lockout', 'vcns-security-automation-manager' ); ?></th>
					<th><?php esc_html_e( 'Actions', 'vcns-security-automation-manager' ); ?></th>
				</tr>
			</thead>
			<tbody>
			<?php foreach ( $policies as $policy ) : ?>
				<?php $form_id = 'wp-sam-policy-form-' . (string) $policy['surface']; ?>
				<tr>
					<td><?php echo esc_html( ucfirst( (string) $policy['surface'] ) ); ?></td>
					<td>
						<select form="<?php echo esc_attr( $form_id ); ?>" name="mode">
							<option value="observe" <?php selected( $policy['mode'], 'observe' ); ?>><?php esc_html_e( 'Observe (never blocks)', 'vcns-security-automation-manager' ); ?></option>
							<option value="enforce" <?php selected( $policy['mode'], 'enforce' ); ?>><?php esc_html_e( 'Enforce', 'vcns-security-automation-manager' ); ?></option>
						</select>
					</td>
					<td>
						<input type="number" min="1" form="<?php echo esc_attr( $form_id ); ?>" name="rate_limit_max_requests" style="width:80px" value="<?php echo esc_attr( (string) $policy['rate_limit_max_requests'] ); ?>" />
						<?php esc_html_e( 'per', 'vcns-security-automation-manager' ); ?>
						<input type="number" min="1" form="<?php echo esc_attr( $form_id ); ?>" name="rate_limit_window_seconds" style="width:80px" value="<?php echo esc_attr( (string) $policy['rate_limit_window_seconds'] ); ?>" />
						<?php esc_html_e( 'sec', 'vcns-security-automation-manager' ); ?>
					</td>
					<td>
						<?php if ( 'login' === $policy['surface'] ) : ?>
						<input type="number" min="1" form="<?php echo esc_attr( $form_id ); ?>" name="login_max_failed_attempts" style="width:70px" value="<?php echo esc_attr( (string) $policy['login_max_failed_attempts'] ); ?>" />
							<?php esc_html_e( 'in', 'vcns-security-automation-manager' ); ?>
						<input type="number" min="1" form="<?php echo esc_attr( $form_id ); ?>" name="login_lockout_seconds" style="width:80px" value="<?php echo esc_attr( (string) $policy['login_lockout_seconds'] ); ?>" />
							<?php esc_html_e( 'sec', 'vcns-security-automation-manager' ); ?>
						<?php else : ?>
						&#8212;
						<?php endif; ?>
					</td>
					<td><button type="submit" form="<?php echo esc_attr( $form_id ); ?>" class="button button-primary"><?php esc_html_e( 'Save', 'vcns-security-automation-manager' ); ?></button></td>
				</tr>
			<?php endforeach; ?>
			</tbody>
		</table>

	<?php elseif ( 'ip-rules' === $tab ) : ?>

		<?php $rules = ( new Ip_Rule_Store() )->all(); ?>

		<table class="widefat fixed striped wp-sam-violations-table" style="margin-top:1em">
			<thead>
				<tr>
					<th><?php esc_html_e( 'Type', 'vcns-security-automation-manager' ); ?></th>
					<th><?php esc_html_e( 'CIDR', 'vcns-security-automation-manager' ); ?></th>
					<th><?php esc_html_e( 'Surface', 'vcns-security-automation-manager' ); ?></th>
					<th><?php esc_html_e( 'Reason', 'vcns-security-automation-manager' ); ?></th>
					<th><?php esc_html_e( 'Expires', 'vcns-security-automation-manager' ); ?></th>
					<th><?php esc_html_e( 'Actions', 'vcns-security-automation-manager' ); ?></th>
				</tr>
			</thead>
			<tbody>
			<?php foreach ( $rules as $rule ) : ?>
			<tr>
				<td><?php echo esc_html( ucfirst( (string) $rule['list_type'] ) ); ?></td>
				<td><code><?php echo esc_html( (string) $rule['cidr'] ); ?></code></td>
				<td><?php echo esc_html( '' !== (string) $rule['surface'] ? ucfirst( (string) $rule['surface'] ) : __( 'All', 'vcns-security-automation-manager' ) ); ?></td>
				<td><?php echo esc_html( (string) $rule['reason'] ); ?></td>
				<td><?php echo esc_html( ! empty( $rule['expires_at'] ) ? (string) $rule['expires_at'] : __( 'Never', 'vcns-security-automation-manager' ) ); ?></td>
				<td>
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

		<h2 style="margin-top:2em"><?php esc_html_e( 'Add a rule', 'vcns-security-automation-manager' ); ?></h2>
		<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
			<?php wp_nonce_field( 'wp_sam_ip_rule_add' ); ?>
			<input type="hidden" name="action" value="wp_sam_ip_rule_add" />
			<table class="form-table">
				<tr>
					<th><label for="list_type"><?php esc_html_e( 'Type', 'vcns-security-automation-manager' ); ?></label></th>
					<td>
						<select id="list_type" name="list_type">
							<option value="block"><?php esc_html_e( 'Block', 'vcns-security-automation-manager' ); ?></option>
							<option value="allow"><?php esc_html_e( 'Allow', 'vcns-security-automation-manager' ); ?></option>
						</select>
					</td>
				</tr>
				<tr>
					<th><label for="cidr"><?php esc_html_e( 'IP or CIDR', 'vcns-security-automation-manager' ); ?></label></th>
					<td><input type="text" id="cidr" name="cidr" required placeholder="203.0.113.42 or 203.0.113.0/24" style="width:100%;max-width:300px" /></td>
				</tr>
				<tr>
					<th><label for="surface"><?php esc_html_e( 'Surface', 'vcns-security-automation-manager' ); ?></label></th>
					<td>
						<select id="surface" name="surface">
							<option value=""><?php esc_html_e( 'All surfaces', 'vcns-security-automation-manager' ); ?></option>
							<?php foreach ( array( 'frontend', 'admin', 'login', 'api' ) as $s ) : ?>
							<option value="<?php echo esc_attr( $s ); ?>"><?php echo esc_html( ucfirst( $s ) ); ?></option>
							<?php endforeach; ?>
						</select>
					</td>
				</tr>
				<tr>
					<th><label for="reason"><?php esc_html_e( 'Reason', 'vcns-security-automation-manager' ); ?></label></th>
					<td><input type="text" id="reason" name="reason" required style="width:100%;max-width:300px" /></td>
				</tr>
				<tr>
					<th><label for="expires_in_hours"><?php esc_html_e( 'Expires after (hours)', 'vcns-security-automation-manager' ); ?></label></th>
					<td><input type="number" id="expires_in_hours" name="expires_in_hours" min="0" placeholder="<?php esc_attr_e( '0 = never', 'vcns-security-automation-manager' ); ?>" style="width:120px" /></td>
				</tr>
			</table>
			<?php submit_button( __( 'Add rule', 'vcns-security-automation-manager' ) ); ?>
		</form>

	<?php elseif ( 'blocks' === $tab ) : ?>

		<?php $blocks = ( new Traffic_Block_Store() )->all_active(); ?>

		<table class="widefat fixed striped wp-sam-violations-table wp-sam-blocks-table" style="margin-top:1em">
			<thead>
				<tr>
					<th><?php esc_html_e( 'IP', 'vcns-security-automation-manager' ); ?></th>
					<th><?php esc_html_e( 'Surface', 'vcns-security-automation-manager' ); ?></th>
					<th><?php esc_html_e( 'Stage', 'vcns-security-automation-manager' ); ?></th>
					<th><?php esc_html_e( 'Reason', 'vcns-security-automation-manager' ); ?></th>
					<th><?php esc_html_e( 'Occurrences', 'vcns-security-automation-manager' ); ?></th>
					<th><?php esc_html_e( 'Blocked Until', 'vcns-security-automation-manager' ); ?></th>
					<th><?php esc_html_e( 'Actions', 'vcns-security-automation-manager' ); ?></th>
				</tr>
			</thead>
			<tbody>
			<?php foreach ( $blocks as $block ) : ?>
			<tr>
				<td><code><?php echo esc_html( (string) $block['ip'] ); ?></code></td>
				<td><?php echo esc_html( ucfirst( (string) $block['surface'] ) ); ?></td>
				<td><?php echo esc_html( str_replace( '_', ' ', ucfirst( (string) $block['stage'] ) ) ); ?></td>
				<td><?php echo esc_html( str_replace( '_', ' ', (string) $block['reason'] ) ); ?></td>
				<td><?php echo esc_html( number_format( (int) $block['occurrence_count'] ) ); ?></td>
				<?php
				$blocked_until_display = '—';
				if ( ! empty( $block['is_persistent'] ) ) {
					$blocked_until_display = __( 'Permanent', 'vcns-security-automation-manager' );
				} elseif ( ! empty( $block['blocked_until'] ) ) {
					$blocked_until_display = (string) $block['blocked_until'];
				}
				?>
				<td><?php echo esc_html( $blocked_until_display ); ?></td>
				<td>
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

	<?php elseif ( 'network-intelligence' === $tab ) : ?>

		<?php
		$ni_subtab          = isset( $_GET['subtab'] ) ? sanitize_text_field( wp_unslash( $_GET['subtab'] ) ) : 'tor'; // phpcs:ignore WordPress.Security.NonceVerification.Recommended
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

			<?php $tor_store = new Tor_Exit_List_Store(); ?>

			<table class="widefat fixed striped wp-sam-violations-table" style="margin-top:1em">
				<tbody>
					<tr>
						<th style="width:200px"><?php esc_html_e( 'Known exit nodes', 'vcns-security-automation-manager' ); ?></th>
						<td><?php echo esc_html( number_format( $tor_store->count() ) ); ?></td>
					</tr>
					<tr>
						<th><?php esc_html_e( 'Last refreshed', 'vcns-security-automation-manager' ); ?></th>
						<td><?php echo esc_html( $tor_store->last_refreshed_at() ?? __( 'Never', 'vcns-security-automation-manager' ) ); ?></td>
					</tr>
					<tr>
						<th><?php esc_html_e( 'Last fetch status', 'vcns-security-automation-manager' ); ?></th>
						<td>
							<?php
							$status = $tor_store->last_fetch_status();
							echo esc_html( '' !== $status ? ucfirst( $status ) : __( 'Not yet run', 'vcns-security-automation-manager' ) );
							?>
						</td>
					</tr>
				</tbody>
			</table>

			<p class="description" style="margin-top:1em">
				<?php esc_html_e( 'Refreshed automatically once a day from the Tor Project\'s own public exit-node list. Tor identity is recorded as context on evidence a detector already produced -- it never implies malicious intent on its own, and nothing here blocks a visitor.', 'vcns-security-automation-manager' ); ?>
			</p>

			<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" style="margin-top:1em">
				<?php wp_nonce_field( 'wp_sam_tor_list_refresh' ); ?>
				<input type="hidden" name="action" value="wp_sam_tor_list_refresh" />
				<?php submit_button( __( 'Refresh Now', 'vcns-security-automation-manager' ), 'secondary', '', false ); ?>
			</form>

		<?php elseif ( 'asn' === $ni_subtab ) : ?>

			<p class="description">
				<?php esc_html_e( 'Free, unauthenticated lookup via Team Cymru -- no account needed. Results are cached for 30 days once looked up, so this only costs a real DNS query the first time a given IP is involved in a detector match.', 'vcns-security-automation-manager' ); ?>
			</p>

			<form method="get" style="margin-top:1em">
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
				$lookup_result = ( new Asn_Lookup_Store() )->resolve( $lookup_ip );
				?>
			<table class="widefat fixed striped wp-sam-violations-table" style="margin-top:1em">
				<tbody>
					<tr>
						<th style="width:200px"><?php esc_html_e( 'IP', 'vcns-security-automation-manager' ); ?></th>
						<td><code><?php echo esc_html( $lookup_ip ); ?></code></td>
					</tr>
					<tr>
						<th><?php esc_html_e( 'ASN', 'vcns-security-automation-manager' ); ?></th>
						<td><?php echo esc_html( null !== $lookup_result['asn'] ? 'AS' . (string) $lookup_result['asn'] : __( 'Not found', 'vcns-security-automation-manager' ) ); ?></td>
					</tr>
					<tr>
						<th><?php esc_html_e( 'Organisation', 'vcns-security-automation-manager' ); ?></th>
						<td><?php echo esc_html( $lookup_result['asn_org'] ?? '—' ); ?></td>
					</tr>
				</tbody>
			</table>
			<?php endif; ?>

		<?php elseif ( 'geoip' === $ni_subtab ) : ?>

			<?php $geo_store = new Geo_Ip_Store(); ?>

			<p class="description">
				<?php esc_html_e( 'Opt-in, using your own IPinfo (ipinfo.io) account -- never a shared VCNS credential. Disabled until you add a token below. MaxMind support is a deliberate later decision, not built yet -- its free tier is a downloaded database, not a live lookup service.', 'vcns-security-automation-manager' ); ?>
				<?php if ( ! $geo_store->is_configured() ) : ?>
				<a href="https://ipinfo.io/signup" target="_blank" rel="noopener noreferrer"><?php esc_html_e( "Don't have a token? Sign up free at ipinfo.io.", 'vcns-security-automation-manager' ); ?></a>
				<?php endif; ?>
			</p>

			<?php if ( $geo_store->token_undecryptable() ) : ?>
			<div class="notice notice-warning inline" style="padding:12px 16px;margin:1em 0">
				<p style="margin-top:0;"><?php esc_html_e( 'A saved IPinfo token could not be decrypted (likely because the site\'s secret keys changed since it was saved). Geo-IP is currently disabled -- re-enter the token below to restore it.', 'vcns-security-automation-manager' ); ?></p>
			</div>
			<?php endif; ?>

			<table class="widefat fixed striped wp-sam-violations-table" style="margin-top:1em;max-width:600px">
				<tbody>
					<tr>
						<th style="width:200px"><?php esc_html_e( 'Status', 'vcns-security-automation-manager' ); ?></th>
						<td><?php echo esc_html( $geo_store->is_configured() ? __( 'Enabled', 'vcns-security-automation-manager' ) : __( 'Disabled -- no token configured', 'vcns-security-automation-manager' ) ); ?></td>
					</tr>
				</tbody>
			</table>

			<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" style="margin-top:1em">
				<?php wp_nonce_field( 'wp_sam_geoip_save_token' ); ?>
				<input type="hidden" name="action" value="wp_sam_geoip_save_token" />
				<label for="ipinfo_token"><?php esc_html_e( 'IPinfo API token', 'vcns-security-automation-manager' ); ?></label><br />
				<input type="password" id="ipinfo_token" name="ipinfo_token" autocomplete="off" placeholder="<?php echo $geo_store->is_configured() ? esc_attr__( 'Saved -- leave blank to keep', 'vcns-security-automation-manager' ) : ''; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- esc_attr__() already escapes. ?>" style="width:100%;max-width:400px" />
				<p>
					<?php submit_button( __( 'Save Token', 'vcns-security-automation-manager' ), 'primary', '', false ); ?>
					<?php if ( $geo_store->is_configured() ) : ?>
					<button type="submit" name="clear_token" value="1" class="button"><?php esc_html_e( 'Clear and Disable', 'vcns-security-automation-manager' ); ?></button>
					<?php endif; ?>
				</p>
			</form>

			<?php if ( $geo_store->is_configured() ) : ?>
			<h3 style="margin-top:1.5em"><?php esc_html_e( 'Geo-IP Lookup', 'vcns-security-automation-manager' ); ?></h3>
			<form method="get" style="margin-top:0.5em">
				<input type="hidden" name="page" value="security-automation-manager-traffic" />
				<input type="hidden" name="tab" value="network-intelligence" />
				<input type="hidden" name="subtab" value="geoip" />
				<label for="geo_lookup_ip" class="screen-reader-text"><?php esc_html_e( 'IP address to look up', 'vcns-security-automation-manager' ); ?></label>
				<input type="text" id="geo_lookup_ip" name="geo_lookup_ip" placeholder="203.0.113.42" value="<?php echo esc_attr( isset( $_GET['geo_lookup_ip'] ) ? sanitize_text_field( wp_unslash( $_GET['geo_lookup_ip'] ) ) : '' ); // phpcs:ignore WordPress.Security.NonceVerification.Recommended ?>" style="width:220px" />
				<?php submit_button( __( 'Look Up', 'vcns-security-automation-manager' ), 'secondary', '', false ); ?>
			</form>

				<?php
				$geo_lookup_ip = isset( $_GET['geo_lookup_ip'] ) ? sanitize_text_field( wp_unslash( $_GET['geo_lookup_ip'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Recommended
				if ( '' !== $geo_lookup_ip ) :
					$geo_result = $geo_store->resolve( $geo_lookup_ip );
					?>
			<table class="widefat fixed striped wp-sam-violations-table" style="margin-top:1em;max-width:600px">
				<tbody>
					<tr>
						<th style="width:200px"><?php esc_html_e( 'IP', 'vcns-security-automation-manager' ); ?></th>
						<td><code><?php echo esc_html( $geo_lookup_ip ); ?></code></td>
					</tr>
					<tr>
						<th><?php esc_html_e( 'Country', 'vcns-security-automation-manager' ); ?></th>
						<td><?php echo esc_html( $geo_result['country'] ?? __( 'Not found', 'vcns-security-automation-manager' ) ); ?></td>
					</tr>
					<tr>
						<th><?php esc_html_e( 'Region', 'vcns-security-automation-manager' ); ?></th>
						<td><?php echo esc_html( $geo_result['region'] ?? '—' ); ?></td>
					</tr>
					<tr>
						<th><?php esc_html_e( 'City', 'vcns-security-automation-manager' ); ?></th>
						<td><?php echo esc_html( $geo_result['city'] ?? '—' ); ?></td>
					</tr>
				</tbody>
			</table>
				<?php endif; ?>
			<?php endif; ?>

			<h3 style="margin-top:2em"><?php esc_html_e( 'Country Block List', 'vcns-security-automation-manager' ); ?></h3>

			<?php if ( ! $geo_store->is_configured() ) : ?>
			<div class="notice notice-warning inline" style="padding:12px 16px;margin:1em 0">
				<p style="margin-top:0"><?php esc_html_e( 'Blocking by country has no effect until a Geo-IP token is configured above -- there is no way to resolve a visitor\'s country without one. Self-lockout protection below is also unavailable until then, for the same reason.', 'vcns-security-automation-manager' ); ?></p>
			</div>
			<?php endif; ?>

			<?php
			$geoip_lockout_key     = 'wp_sam_geoip_lockout_pending_' . get_current_user_id();
			$geoip_lockout_pending = get_transient( $geoip_lockout_key );
			delete_transient( $geoip_lockout_key );
			$geoip_confirming = is_array( $geoip_lockout_pending );

			$geoip_country_rules = array_filter(
				( new Network_Rule_Store() )->all(),
				static fn( $rule ) => 'country' === $rule['rule_type'] && '' === (string) $rule['surface']
			);
			$geoip_blocked_codes = array_map( static fn( $rule ) => (string) $rule['value'], $geoip_country_rules );
			$geoip_checked_codes = $geoip_confirming ? (array) $geoip_lockout_pending['countries'] : $geoip_blocked_codes;
			?>

			<p class="description">
				<?php esc_html_e( 'Every country defaults to Allow. Tick a country to Block it -- nothing changes until you click Save below.', 'vcns-security-automation-manager' ); ?>
			</p>

			<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" style="margin-top:1em">
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
				<div class="wp-sam-country-grid">
					<?php foreach ( Iso_Countries::all() as $code => $name ) : ?>
					<label>
						<input type="checkbox" name="blocked_countries[]" value="<?php echo esc_attr( $code ); ?>" <?php checked( in_array( $code, $geoip_checked_codes, true ) ); ?> />
						<?php echo esc_html( $name ); ?> <code><?php echo esc_html( $code ); ?></code>
					</label>
					<?php endforeach; ?>
				</div>
				<?php submit_button( __( 'Save Country Block List', 'vcns-security-automation-manager' ) ); ?>
			</form>

		<?php elseif ( 'well-known' === $ni_subtab ) : ?>

			<?php $robots_rules_store = new Robots_Rules_Store(); ?>

			<h2><?php esc_html_e( 'Robots.txt', 'vcns-security-automation-manager' ); ?></h2>
			<table class="widefat fixed striped wp-sam-violations-table" style="margin-top:1em">
				<tbody>
					<tr>
						<th style="width:200px"><?php esc_html_e( 'Cached disallow rules', 'vcns-security-automation-manager' ); ?></th>
						<td><?php echo esc_html( number_format( count( $robots_rules_store->rules() ) ) ); ?></td>
					</tr>
					<tr>
						<th><?php esc_html_e( 'Last refreshed', 'vcns-security-automation-manager' ); ?></th>
						<td><?php echo esc_html( $robots_rules_store->last_refreshed_at() ?? __( 'Never', 'vcns-security-automation-manager' ) ); ?></td>
					</tr>
					<tr>
						<th><?php esc_html_e( 'Last fetch status', 'vcns-security-automation-manager' ); ?></th>
						<td>
							<?php
							$robots_status = $robots_rules_store->last_fetch_status();
							echo esc_html( '' !== $robots_status ? ucfirst( $robots_status ) : __( 'Not yet run', 'vcns-security-automation-manager' ) );
							?>
						</td>
					</tr>
				</tbody>
			</table>

			<p class="description" style="margin-top:1em">
				<?php esc_html_e( 'Refreshed automatically once a day from this site\'s own /robots.txt, fetched the same way a real crawler would. Used only to check whether a source already recognised as a known crawler/scanner vendor is requesting a path this site disallows -- an ordinary visitor is never evaluated against these rules.', 'vcns-security-automation-manager' ); ?>
			</p>

			<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" style="margin-top:1em">
				<?php wp_nonce_field( 'wp_sam_robots_rules_refresh' ); ?>
				<input type="hidden" name="action" value="wp_sam_robots_rules_refresh" />
				<?php submit_button( __( 'Refresh Now', 'vcns-security-automation-manager' ), 'secondary', '', false ); ?>
			</form>

			<?php $agents_rules_store = new Agents_Rules_Store(); ?>

			<h2 style="margin-top:2em"><?php esc_html_e( 'Agents.txt', 'vcns-security-automation-manager' ); ?></h2>
			<table class="widefat fixed striped wp-sam-violations-table" style="margin-top:1em">
				<tbody>
					<tr>
						<th style="width:200px"><?php esc_html_e( 'Cached disallow rules', 'vcns-security-automation-manager' ); ?></th>
						<td><?php echo esc_html( number_format( count( $agents_rules_store->rules() ) ) ); ?></td>
					</tr>
					<tr>
						<th><?php esc_html_e( 'Last refreshed', 'vcns-security-automation-manager' ); ?></th>
						<td><?php echo esc_html( $agents_rules_store->last_refreshed_at() ?? __( 'Never', 'vcns-security-automation-manager' ) ); ?></td>
					</tr>
					<tr>
						<th><?php esc_html_e( 'Last fetch status', 'vcns-security-automation-manager' ); ?></th>
						<td>
							<?php
							$agents_status = $agents_rules_store->last_fetch_status();
							echo esc_html( '' !== $agents_status ? ucfirst( $agents_status ) : __( 'Not yet run', 'vcns-security-automation-manager' ) );
							?>
						</td>
					</tr>
				</tbody>
			</table>

			<p class="description" style="margin-top:1em">
				<?php esc_html_e( 'agents.txt is an emerging convention some AI crawlers support for scoping what an AI agent may access, using the same syntax as robots.txt. Refreshed automatically once a day; used the same way robots.txt rules are, only against a source already recognised as a known crawler/scanner vendor.', 'vcns-security-automation-manager' ); ?>
			</p>

			<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" style="margin-top:1em">
				<?php wp_nonce_field( 'wp_sam_agents_rules_refresh' ); ?>
				<input type="hidden" name="action" value="wp_sam_agents_rules_refresh" />
				<?php submit_button( __( 'Refresh Now', 'vcns-security-automation-manager' ), 'secondary', '', false ); ?>
			</form>

			<?php $security_txt_store = new Security_Txt_Store(); ?>

			<h2 style="margin-top:2em"><?php esc_html_e( 'Security.txt', 'vcns-security-automation-manager' ); ?></h2>
			<table class="widefat fixed striped wp-sam-violations-table" style="margin-top:1em">
				<tbody>
					<tr>
						<th style="width:200px"><?php esc_html_e( 'Present', 'vcns-security-automation-manager' ); ?></th>
						<td><?php echo esc_html( $security_txt_store->is_present() ? __( 'Yes', 'vcns-security-automation-manager' ) : __( 'No', 'vcns-security-automation-manager' ) ); ?></td>
					</tr>
					<tr>
						<th><?php esc_html_e( 'Expires', 'vcns-security-automation-manager' ); ?></th>
						<td>
							<?php
							$security_txt_expires = $security_txt_store->fields()['Expires'][0] ?? null;
							if ( null === $security_txt_expires ) {
								echo esc_html( '—' );
							} else {
								echo esc_html( $security_txt_expires );
								if ( $security_txt_store->is_expired() ) {
									echo ' <strong style="color:#a94442">' . esc_html__( '(expired)', 'vcns-security-automation-manager' ) . '</strong>'; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- esc_html__() already escapes; the surrounding markup is a static literal.
								}
							}
							?>
						</td>
					</tr>
					<tr>
						<th><?php esc_html_e( 'Last refreshed', 'vcns-security-automation-manager' ); ?></th>
						<td><?php echo esc_html( $security_txt_store->last_refreshed_at() ?? __( 'Never', 'vcns-security-automation-manager' ) ); ?></td>
					</tr>
					<tr>
						<th><?php esc_html_e( 'Last fetch status', 'vcns-security-automation-manager' ); ?></th>
						<td>
							<?php
							$security_txt_status = $security_txt_store->last_fetch_status();
							echo esc_html( '' !== $security_txt_status ? ucfirst( $security_txt_status ) : __( 'Not yet run', 'vcns-security-automation-manager' ) );
							?>
						</td>
					</tr>
				</tbody>
			</table>

			<p class="description" style="margin-top:1em">
				<?php esc_html_e( 'Refreshed automatically once a day from this site\'s own /.well-known/security.txt (falling back to the legacy /security.txt location). Recorded for visibility only -- an expired file is a hygiene signal worth acting on, but nothing here evaluates or blocks a visitor.', 'vcns-security-automation-manager' ); ?>
			</p>

			<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" style="margin-top:1em">
				<?php wp_nonce_field( 'wp_sam_security_txt_refresh' ); ?>
				<input type="hidden" name="action" value="wp_sam_security_txt_refresh" />
				<?php submit_button( __( 'Refresh Now', 'vcns-security-automation-manager' ), 'secondary', '', false ); ?>
			</form>

			<?php $humans_txt_store = new Humans_Txt_Store(); ?>

			<h2 style="margin-top:2em"><?php esc_html_e( 'Humans.txt', 'vcns-security-automation-manager' ); ?></h2>
			<table class="widefat fixed striped wp-sam-violations-table" style="margin-top:1em">
				<tbody>
					<tr>
						<th style="width:200px"><?php esc_html_e( 'Present', 'vcns-security-automation-manager' ); ?></th>
						<td><?php echo esc_html( $humans_txt_store->is_present() ? __( 'Yes', 'vcns-security-automation-manager' ) : __( 'No', 'vcns-security-automation-manager' ) ); ?></td>
					</tr>
					<tr>
						<th><?php esc_html_e( 'Last refreshed', 'vcns-security-automation-manager' ); ?></th>
						<td><?php echo esc_html( $humans_txt_store->last_refreshed_at() ?? __( 'Never', 'vcns-security-automation-manager' ) ); ?></td>
					</tr>
					<tr>
						<th><?php esc_html_e( 'Last fetch status', 'vcns-security-automation-manager' ); ?></th>
						<td>
							<?php
							$humans_txt_status = $humans_txt_store->last_fetch_status();
							echo esc_html( '' !== $humans_txt_status ? ucfirst( $humans_txt_status ) : __( 'Not yet run', 'vcns-security-automation-manager' ) );
							?>
						</td>
					</tr>
				</tbody>
			</table>

			<p class="description" style="margin-top:1em">
				<?php esc_html_e( 'An informal credits/colophon convention with no rules of its own -- recorded only for the same presence/last-fetch visibility every well-known file here gets, so a source examining it is correlatable against its other activity.', 'vcns-security-automation-manager' ); ?>
			</p>

			<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" style="margin-top:1em">
				<?php wp_nonce_field( 'wp_sam_humans_txt_refresh' ); ?>
				<input type="hidden" name="action" value="wp_sam_humans_txt_refresh" />
				<?php submit_button( __( 'Refresh Now', 'vcns-security-automation-manager' ), 'secondary', '', false ); ?>
			</form>

			<?php $ads_txt_store = new Ads_Txt_Store(); ?>

			<h2 style="margin-top:2em"><?php esc_html_e( 'Ads.txt', 'vcns-security-automation-manager' ); ?></h2>
			<table class="widefat fixed striped wp-sam-violations-table" style="margin-top:1em">
				<tbody>
					<tr>
						<th style="width:200px"><?php esc_html_e( 'Authorised-seller records', 'vcns-security-automation-manager' ); ?></th>
						<td><?php echo esc_html( number_format( count( $ads_txt_store->records() ) ) ); ?></td>
					</tr>
					<tr>
						<th><?php esc_html_e( 'Last refreshed', 'vcns-security-automation-manager' ); ?></th>
						<td><?php echo esc_html( $ads_txt_store->last_refreshed_at() ?? __( 'Never', 'vcns-security-automation-manager' ) ); ?></td>
					</tr>
					<tr>
						<th><?php esc_html_e( 'Last fetch status', 'vcns-security-automation-manager' ); ?></th>
						<td>
							<?php
							$ads_txt_status = $ads_txt_store->last_fetch_status();
							echo esc_html( '' !== $ads_txt_status ? ucfirst( $ads_txt_status ) : __( 'Not yet run', 'vcns-security-automation-manager' ) );
							?>
						</td>
					</tr>
				</tbody>
			</table>

			<p class="description" style="margin-top:1em">
				<?php esc_html_e( 'Refreshed automatically once a day. A sudden drop in record count or a fetch failure can indicate unauthorised tampering (a known ad-fraud vector) as easily as a legitimate change -- worth a look either way.', 'vcns-security-automation-manager' ); ?>
			</p>

			<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" style="margin-top:1em">
				<?php wp_nonce_field( 'wp_sam_ads_txt_refresh' ); ?>
				<input type="hidden" name="action" value="wp_sam_ads_txt_refresh" />
				<?php submit_button( __( 'Refresh Now', 'vcns-security-automation-manager' ), 'secondary', '', false ); ?>
			</form>

			<?php $app_ads_txt_store = new App_Ads_Txt_Store(); ?>

			<h2 style="margin-top:2em"><?php esc_html_e( 'App-Ads.txt', 'vcns-security-automation-manager' ); ?></h2>
			<table class="widefat fixed striped wp-sam-violations-table" style="margin-top:1em">
				<tbody>
					<tr>
						<th style="width:200px"><?php esc_html_e( 'Authorised-seller records', 'vcns-security-automation-manager' ); ?></th>
						<td><?php echo esc_html( number_format( count( $app_ads_txt_store->records() ) ) ); ?></td>
					</tr>
					<tr>
						<th><?php esc_html_e( 'Last refreshed', 'vcns-security-automation-manager' ); ?></th>
						<td><?php echo esc_html( $app_ads_txt_store->last_refreshed_at() ?? __( 'Never', 'vcns-security-automation-manager' ) ); ?></td>
					</tr>
					<tr>
						<th><?php esc_html_e( 'Last fetch status', 'vcns-security-automation-manager' ); ?></th>
						<td>
							<?php
							$app_ads_txt_status = $app_ads_txt_store->last_fetch_status();
							echo esc_html( '' !== $app_ads_txt_status ? ucfirst( $app_ads_txt_status ) : __( 'Not yet run', 'vcns-security-automation-manager' ) );
							?>
						</td>
					</tr>
				</tbody>
			</table>

			<p class="description" style="margin-top:1em">
				<?php esc_html_e( 'The same IAB authorised-sellers format as Ads.txt above, applied to mobile-app inventory. Refreshed automatically once a day; tracked separately since it is a distinct file this site serves.', 'vcns-security-automation-manager' ); ?>
			</p>

			<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" style="margin-top:1em">
				<?php wp_nonce_field( 'wp_sam_app_ads_txt_refresh' ); ?>
				<input type="hidden" name="action" value="wp_sam_app_ads_txt_refresh" />
				<?php submit_button( __( 'Refresh Now', 'vcns-security-automation-manager' ), 'secondary', '', false ); ?>
			</form>

		<?php elseif ( 'network-rules' === $ni_subtab ) : ?>

			<?php $network_rules = ( new Network_Rule_Store() )->all(); ?>

			<p class="description">
				<?php esc_html_e( "Block traffic by ASN or country, checked alongside IP Rules -- an explicit decision, applied regardless of a surface's observe/enforce mode. Adding the first rule here is what switches ASN/Geo-IP resolution on for every request; with no rules configured, nothing here costs anything. The Geo-IP tab's Country Block List above manages all-surfaces country rules with a friendlier toggle grid; use this form for ASN rules or a per-surface country exception.", 'vcns-security-automation-manager' ); ?>
			</p>

			<table class="widefat fixed striped wp-sam-violations-table" style="margin-top:1em">
				<thead>
					<tr>
						<th><?php esc_html_e( 'Type', 'vcns-security-automation-manager' ); ?></th>
						<th><?php esc_html_e( 'Value', 'vcns-security-automation-manager' ); ?></th>
						<th><?php esc_html_e( 'Surface', 'vcns-security-automation-manager' ); ?></th>
						<th><?php esc_html_e( 'Reason', 'vcns-security-automation-manager' ); ?></th>
						<th><?php esc_html_e( 'Actions', 'vcns-security-automation-manager' ); ?></th>
					</tr>
				</thead>
				<tbody>
				<?php foreach ( $network_rules as $network_rule ) : ?>
				<tr>
					<td><?php echo esc_html( 'asn' === $network_rule['rule_type'] ? __( 'ASN', 'vcns-security-automation-manager' ) : __( 'Country', 'vcns-security-automation-manager' ) ); ?></td>
					<td><code><?php echo esc_html( 'asn' === $network_rule['rule_type'] ? 'AS' . (string) $network_rule['value'] : (string) $network_rule['value'] ); ?></code></td>
					<td><?php echo esc_html( '' !== (string) $network_rule['surface'] ? ucfirst( (string) $network_rule['surface'] ) : __( 'All', 'vcns-security-automation-manager' ) ); ?></td>
					<td><?php echo esc_html( (string) $network_rule['reason'] ); ?></td>
					<td>
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

			<h3 style="margin-top:1.5em"><?php esc_html_e( 'Add a network rule', 'vcns-security-automation-manager' ); ?></h3>
			<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
				<?php wp_nonce_field( 'wp_sam_network_rule_add' ); ?>
				<input type="hidden" name="action" value="wp_sam_network_rule_add" />
				<table class="form-table">
					<tr>
						<th><label for="rule_type"><?php esc_html_e( 'Type', 'vcns-security-automation-manager' ); ?></label></th>
						<td>
							<select id="rule_type" name="rule_type">
								<option value="asn"><?php esc_html_e( 'ASN', 'vcns-security-automation-manager' ); ?></option>
								<option value="country"><?php esc_html_e( 'Country', 'vcns-security-automation-manager' ); ?></option>
							</select>
						</td>
					</tr>
					<tr>
						<th><label for="value"><?php esc_html_e( 'Value', 'vcns-security-automation-manager' ); ?></label></th>
						<td>
							<input type="text" id="value" name="value" required placeholder="<?php esc_attr_e( 'AS15169, or a two-letter country code such as CN', 'vcns-security-automation-manager' ); ?>" style="width:100%;max-width:300px" />
						</td>
					</tr>
					<tr>
						<th><label for="network_rule_surface"><?php esc_html_e( 'Surface', 'vcns-security-automation-manager' ); ?></label></th>
						<td>
							<select id="network_rule_surface" name="surface">
								<option value=""><?php esc_html_e( 'All surfaces', 'vcns-security-automation-manager' ); ?></option>
								<?php foreach ( array( 'frontend', 'admin', 'login', 'api' ) as $network_rule_surface ) : ?>
								<option value="<?php echo esc_attr( $network_rule_surface ); ?>"><?php echo esc_html( ucfirst( $network_rule_surface ) ); ?></option>
								<?php endforeach; ?>
							</select>
						</td>
					</tr>
					<tr>
						<th><label for="network_rule_reason"><?php esc_html_e( 'Reason', 'vcns-security-automation-manager' ); ?></label></th>
						<td><input type="text" id="network_rule_reason" name="reason" required style="width:100%;max-width:300px" /></td>
					</tr>
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

		<p class="description" style="max-width:700px">
			<?php esc_html_e( 'A detector left on "Observe only" only ever records evidence -- it never contributes to blocking. Switching one to "Enforce" feeds the exact same progressive-response ladder as rate limiting (Warn -> Throttle -> Temporary block -> Extended block), still gated by that surface\'s own Observe/Enforce mode on the Policy tab above. Not every family allows Enforce -- some are reconnaissance signals only, by design.', 'vcns-security-automation-manager' ); ?>
		</p>

		<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" style="margin-top:1em">
			<?php wp_nonce_field( 'wp_sam_detector_policy_update' ); ?>
			<input type="hidden" name="action" value="wp_sam_detector_policy_update" />

			<table class="widefat fixed striped wp-sam-violations-table">
				<thead>
					<tr>
						<th style="width:220px"><?php esc_html_e( 'Detector', 'vcns-security-automation-manager' ); ?></th>
						<th style="width:200px"><?php esc_html_e( 'Family', 'vcns-security-automation-manager' ); ?></th>
						<th style="width:80px"><?php esc_html_e( 'Enabled', 'vcns-security-automation-manager' ); ?></th>
						<th><?php esc_html_e( 'Control action', 'vcns-security-automation-manager' ); ?></th>
					</tr>
				</thead>
				<tbody>
				<?php foreach ( $detectors as $detector ) : ?>
					<?php
					$allowed      = $detector->allowed_control_actions();
					$effective    = $detector_policies->control_action_for( $detector );
					$field_prefix = 'detector[' . $detector->id() . ']';
					?>
					<tr>
						<td style="white-space:nowrap"><code><?php echo esc_html( $detector->id() ); ?></code></td>
						<td><?php echo esc_html( $detector->family() ); ?></td>
						<td>
							<input type="checkbox" name="<?php echo esc_attr( $field_prefix ); ?>[enabled]" value="1" <?php checked( $detector_policies->is_enabled( $detector->id() ) ); ?> />
						</td>
						<td>
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
								<?php esc_html_e( 'Observe only (fixed)', 'vcns-security-automation-manager' ); ?>
							<?php endif; ?>
						</td>
					</tr>
				<?php endforeach; ?>
				<?php if ( empty( $detectors ) ) : ?>
					<tr>
						<td colspan="4"><p><?php esc_html_e( 'No detectors registered.', 'vcns-security-automation-manager' ); ?></p></td>
					</tr>
				<?php endif; ?>
				</tbody>
			</table>

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

		<p class="description" style="max-width:700px">
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

		<table class="widefat fixed striped wp-sam-violations-table" style="margin-top:1em">
			<thead>
				<tr>
					<th><?php esc_html_e( 'Name', 'vcns-security-automation-manager' ); ?></th>
					<th><?php esc_html_e( 'Pattern', 'vcns-security-automation-manager' ); ?></th>
					<th><?php esc_html_e( 'Matches against', 'vcns-security-automation-manager' ); ?></th>
					<th><?php esc_html_e( 'Severity', 'vcns-security-automation-manager' ); ?></th>
					<th><?php esc_html_e( 'Surfaces', 'vcns-security-automation-manager' ); ?></th>
					<th><?php esc_html_e( 'Actions', 'vcns-security-automation-manager' ); ?></th>
				</tr>
			</thead>
			<tbody>
			<?php foreach ( $custom_rules as $rule ) : ?>
				<?php $rule_surfaces = json_decode( (string) $rule['surfaces'], true ); ?>
				<tr>
					<td><?php echo esc_html( (string) $rule['name'] ); ?></td>
					<td><code><?php echo esc_html( (string) $rule['pattern'] ); ?></code></td>
					<td><?php echo esc_html( $subject_field_labels[ $rule['subject_field'] ] ?? (string) $rule['subject_field'] ); ?></td>
					<td><?php echo esc_html( $severity_labels[ $rule['severity'] ] ?? (string) $rule['severity'] ); ?></td>
					<td><?php echo esc_html( ! empty( $rule_surfaces ) ? implode( ', ', array_map( 'ucfirst', $rule_surfaces ) ) : __( 'All', 'vcns-security-automation-manager' ) ); ?></td>
					<td style="white-space:nowrap">
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
