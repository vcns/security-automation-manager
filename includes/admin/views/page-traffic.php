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

use WP_SAM\Intelligence\Asn_Lookup_Store;
use WP_SAM\Intelligence\Detector_Policy_Store;
use WP_SAM\Intelligence\Detector_Registry;
use WP_SAM\Intelligence\Geo_Ip_Store;
use WP_SAM\Intelligence\Ip_Rule_Store;
use WP_SAM\Intelligence\Tor_Exit_List_Store;
use WP_SAM\Intelligence\Traffic_Block_Store;
use WP_SAM\Intelligence\Traffic_Policy_Store;

$base_url     = admin_url( 'admin.php?page=security-automation-manager-traffic' );
$tab          = isset( $_GET['tab'] ) ? sanitize_text_field( wp_unslash( $_GET['tab'] ) ) : 'policy'; // phpcs:ignore WordPress.Security.NonceVerification.Recommended
$allowed_tabs = array( 'policy', 'ip-rules', 'blocks', 'network-intelligence', 'detectors' );
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
		<h2 style="margin-top:2em"><?php echo esc_html( ucfirst( (string) $policy['surface'] ) ); ?></h2>
		<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
			<?php wp_nonce_field( 'wp_sam_traffic_policy_update' ); ?>
			<input type="hidden" name="action" value="wp_sam_traffic_policy_update" />
			<input type="hidden" name="surface" value="<?php echo esc_attr( (string) $policy['surface'] ); ?>" />
			<table class="form-table">
				<tr>
					<th><?php esc_html_e( 'Mode', 'vcns-security-automation-manager' ); ?></th>
					<td>
						<select name="mode">
							<option value="observe" <?php selected( $policy['mode'], 'observe' ); ?>><?php esc_html_e( 'Observe (never blocks)', 'vcns-security-automation-manager' ); ?></option>
							<option value="enforce" <?php selected( $policy['mode'], 'enforce' ); ?>><?php esc_html_e( 'Enforce', 'vcns-security-automation-manager' ); ?></option>
						</select>
					</td>
				</tr>
				<tr>
					<th><?php esc_html_e( 'Rate limit', 'vcns-security-automation-manager' ); ?></th>
					<td>
						<input type="number" min="1" name="rate_limit_max_requests" style="width:90px" value="<?php echo esc_attr( (string) $policy['rate_limit_max_requests'] ); ?>" />
						<?php esc_html_e( 'requests per', 'vcns-security-automation-manager' ); ?>
						<input type="number" min="1" name="rate_limit_window_seconds" style="width:90px" value="<?php echo esc_attr( (string) $policy['rate_limit_window_seconds'] ); ?>" />
						<?php esc_html_e( 'seconds', 'vcns-security-automation-manager' ); ?>
					</td>
				</tr>
				<?php if ( 'login' === $policy['surface'] ) : ?>
				<tr>
					<th><?php esc_html_e( 'Failed login lockout', 'vcns-security-automation-manager' ); ?></th>
					<td>
						<input type="number" min="1" name="login_max_failed_attempts" style="width:90px" value="<?php echo esc_attr( (string) $policy['login_max_failed_attempts'] ); ?>" />
						<?php esc_html_e( 'failed attempts within', 'vcns-security-automation-manager' ); ?>
						<input type="number" min="1" name="login_lockout_seconds" style="width:90px" value="<?php echo esc_attr( (string) $policy['login_lockout_seconds'] ); ?>" />
						<?php esc_html_e( 'seconds', 'vcns-security-automation-manager' ); ?>
					</td>
				</tr>
				<?php else : ?>
					<input type="hidden" name="login_max_failed_attempts" value="<?php echo esc_attr( (string) $policy['login_max_failed_attempts'] ); ?>" />
					<input type="hidden" name="login_lockout_seconds" value="<?php echo esc_attr( (string) $policy['login_lockout_seconds'] ); ?>" />
				<?php endif; ?>
			</table>
			<?php submit_button( __( 'Save', 'vcns-security-automation-manager' ) ); ?>
		</form>
		<?php endforeach; ?>

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

		<table class="widefat fixed striped wp-sam-violations-table" style="margin-top:1em">
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

		<?php $tor_store = new Tor_Exit_List_Store(); ?>

		<h2><?php esc_html_e( 'Tor Exit List', 'vcns-security-automation-manager' ); ?></h2>
		<table class="widefat fixed striped wp-sam-violations-table" style="margin-top:1em;max-width:600px">
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

		<p class="description" style="margin-top:1em;max-width:600px">
			<?php esc_html_e( 'Refreshed automatically once a day from the Tor Project\'s own public exit-node list. Tor identity is recorded as context on evidence a detector already produced -- it never implies malicious intent on its own, and nothing here blocks a visitor.', 'vcns-security-automation-manager' ); ?>
		</p>

		<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" style="margin-top:1em">
			<?php wp_nonce_field( 'wp_sam_tor_list_refresh' ); ?>
			<input type="hidden" name="action" value="wp_sam_tor_list_refresh" />
			<?php submit_button( __( 'Refresh Now', 'vcns-security-automation-manager' ), 'secondary', '', false ); ?>
		</form>

		<h2 style="margin-top:2em"><?php esc_html_e( 'ASN Lookup', 'vcns-security-automation-manager' ); ?></h2>
		<p class="description" style="max-width:600px">
			<?php esc_html_e( 'Free, unauthenticated lookup via Team Cymru -- no account needed. Results are cached for 30 days once looked up, so this only costs a real DNS query the first time a given IP is involved in a detector match.', 'vcns-security-automation-manager' ); ?>
		</p>

		<form method="get" style="margin-top:1em">
			<input type="hidden" name="page" value="security-automation-manager-traffic" />
			<input type="hidden" name="tab" value="network-intelligence" />
			<label for="lookup_ip" class="screen-reader-text"><?php esc_html_e( 'IP address to look up', 'vcns-security-automation-manager' ); ?></label>
			<input type="text" id="lookup_ip" name="lookup_ip" placeholder="203.0.113.42" value="<?php echo esc_attr( isset( $_GET['lookup_ip'] ) ? sanitize_text_field( wp_unslash( $_GET['lookup_ip'] ) ) : '' ); // phpcs:ignore WordPress.Security.NonceVerification.Recommended ?>" style="width:220px" />
			<?php submit_button( __( 'Look Up', 'vcns-security-automation-manager' ), 'secondary', '', false ); ?>
		</form>

		<?php
		$lookup_ip = isset( $_GET['lookup_ip'] ) ? sanitize_text_field( wp_unslash( $_GET['lookup_ip'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Recommended
		if ( '' !== $lookup_ip ) :
			$lookup_result = ( new Asn_Lookup_Store() )->resolve( $lookup_ip );
			?>
		<table class="widefat fixed striped wp-sam-violations-table" style="margin-top:1em;max-width:600px">
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

		<?php $geo_store = new Geo_Ip_Store(); ?>

		<h2 style="margin-top:2em"><?php esc_html_e( 'Geo-IP', 'vcns-security-automation-manager' ); ?></h2>
		<p class="description" style="max-width:600px">
			<?php esc_html_e( 'Opt-in, using your own IPinfo (ipinfo.io) account -- never a shared VCNS credential. Disabled until you add a token below. MaxMind support is a deliberate later decision, not built yet -- its free tier is a downloaded database, not a live lookup service.', 'vcns-security-automation-manager' ); ?>
		</p>

		<?php if ( $geo_store->token_undecryptable() ) : ?>
		<div class="notice notice-warning inline" style="padding:12px 16px;margin:1em 0;max-width:600px">
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

	<?php endif; ?>
</div>
