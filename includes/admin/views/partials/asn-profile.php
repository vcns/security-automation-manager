<?php
/**
 * Admin partial: one autonomous system (AS), opened from its AS number on
 * Control → Traffic Controls → Network Intelligence → ASN Lookup (or from
 * an ASN rule on Network Rules).
 *
 * Shows what the regional registry records for the AS, whether it is
 * already blocked, and the addresses this site has recorded from it, each
 * with a way to block it. The block buttons only pre-fill the Network
 * Rules or IP Rules form; nothing is blocked until that form is submitted,
 * and both forms warn first if the rule would block the administrator's
 * own address. Its full list of routed ranges isn't kept here, so it links
 * to two public BGP tools that show it.
 *
 * Rendered by page-traffic.php.
 *
 * @var int    $asn_profile The AS number.
 * @var string $ni_base_url The Network Intelligence tab's URL.
 * @var string $base_url    The Traffic Controls page's URL.
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use WP_SAM\Intelligence\Asn_Lookup_Store;
use WP_SAM\Intelligence\Ip_Rule_Store;
use WP_SAM\Intelligence\Iso_Countries;
use WP_SAM\Intelligence\Network_Rule_Store;
use WP_SAM\Intelligence\Scanner_Identity_Store;

$asn_details   = ( new Asn_Lookup_Store() )->describe( $asn_profile );
$asn_label     = 'AS' . $asn_profile;
$asn_addresses = ( new Scanner_Identity_Store() )->addresses_for_asn( $asn_profile );
$asn_rules     = array_filter(
	( new Network_Rule_Store() )->all(),
	static fn( $rule ) => 'asn' === $rule['rule_type'] && (string) $asn_profile === (string) $rule['value']
);
$asn_surfaces  = array_map( static fn( $rule ) => (string) $rule['surface'], $asn_rules );

// Only every-surface, unexpired IP block rules count as "blocked" below,
// matching what the ASN Lookup result itself shows.
$asn_now        = current_time( 'mysql', true );
$asn_ip_blocks  = array_filter(
	( new Ip_Rule_Store() )->all(),
	static fn( $rule ) => 'block' === $rule['list_type'] && '' === (string) $rule['surface'] && ( empty( $rule['expires_at'] ) || (string) $rule['expires_at'] >= $asn_now )
);
$asn_ip_store   = new Ip_Rule_Store();
$asn_ip_blocked = static function ( string $ip ) use ( $asn_ip_blocks, $asn_ip_store ): bool {
	foreach ( $asn_ip_blocks as $rule ) {
		if ( $asn_ip_store->covers( (string) $rule['cidr'], $ip ) ) {
			return true;
		}
	}
	return false;
};
$asn_full_name  = $asn_label . ( null !== $asn_details['name'] ? ', ' . $asn_details['name'] : '' );
/* translators: %s: AS number and holder, e.g. "AS15169, GOOGLE, US" */
$asn_block_reason = sprintf( __( 'Blocked from ASN Lookup: %s', 'vcns-security-automation-manager' ), $asn_full_name );
/* translators: %s: AS number and holder, e.g. "AS15169, GOOGLE, US" */
$asn_seen_reason = sprintf( __( 'Seen from %s', 'vcns-security-automation-manager' ), $asn_full_name );

$asn_registries = array(
	'afrinic' => 'AFRINIC',
	'apnic'   => 'APNIC',
	'arin'    => 'ARIN',
	'lacnic'  => 'LACNIC',
	'ripencc' => 'RIPE NCC',
);

$asn_block_url = add_query_arg(
	array(
		'subtab'      => 'network-rules',
		'rule_type'   => 'asn',
		'rule_value'  => $asn_label,
		'rule_reason' => $asn_block_reason,
	),
	$ni_base_url
) . '#wp-sam-network-rule-add';

$asn_ip_rule_url = add_query_arg(
	array(
		'tab'    => 'ip-rules',
		'reason' => $asn_seen_reason,
	),
	$base_url
);

$asn_back_ip  = isset( $_GET['lookup_ip'] ) ? sanitize_text_field( wp_unslash( $_GET['lookup_ip'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Recommended
$asn_back_url = add_query_arg(
	array_filter(
		array(
			'subtab'    => 'asn',
			'lookup_ip' => $asn_back_ip,
		)
	),
	$ni_base_url
);
?>

<p><a href="<?php echo esc_url( $asn_back_url ); ?>">&larr; <?php esc_html_e( 'Back to ASN Lookup', 'vcns-security-automation-manager' ); ?></a></p>

<h3 style="margin-bottom:0.25em"><?php echo esc_html( $asn_label . ( null !== $asn_details['name'] ? ' · ' . $asn_details['name'] : '' ) ); ?></h3>
<p class="description" style="margin-top:0">
	<?php esc_html_e( 'An autonomous system is one organisation\'s network on the internet, such as an internet provider or a hosting company. Blocking it blocks every address it routes.', 'vcns-security-automation-manager' ); ?>
</p>

<div class="wp-sam-table-wrap">
<table class="widefat striped wp-sam-table wp-sam-asn-profile-table" style="margin-top:1em">
	<thead>
		<tr>
			<th class="wp-sam-col-description"><?php esc_html_e( 'Organisation', 'vcns-security-automation-manager' ); ?></th>
			<th class="wp-sam-col-primary"><?php esc_html_e( 'Registered in', 'vcns-security-automation-manager' ); ?></th>
			<th class="wp-sam-col-compact"><?php esc_html_e( 'Registry', 'vcns-security-automation-manager' ); ?></th>
			<th class="wp-sam-col-datetime"><?php esc_html_e( 'Allocated', 'vcns-security-automation-manager' ); ?></th>
			<th class="wp-sam-col-status"><?php esc_html_e( 'Blocked', 'vcns-security-automation-manager' ); ?></th>
			<th class="wp-sam-col-actions"><?php esc_html_e( 'Actions', 'vcns-security-automation-manager' ); ?></th>
		</tr>
	</thead>
	<tbody>
		<tr>
			<td class="wp-sam-col-description"><?php echo esc_html( $asn_details['name'] ?? __( 'Not found', 'vcns-security-automation-manager' ) ); ?></td>
			<td class="wp-sam-col-primary">
				<?php
				echo esc_html(
					null !== $asn_details['country']
						/* translators: 1: country name, 2: two-letter country code */
						? sprintf( __( '%1$s (%2$s)', 'vcns-security-automation-manager' ), Iso_Countries::all()[ $asn_details['country'] ] ?? $asn_details['country'], $asn_details['country'] )
						: '—'
				);
				?>
			</td>
			<td class="wp-sam-col-compact"><?php echo esc_html( null !== $asn_details['registry'] ? ( $asn_registries[ $asn_details['registry'] ] ?? strtoupper( $asn_details['registry'] ) ) : '—' ); ?></td>
			<td class="wp-sam-col-datetime"><?php echo esc_html( $asn_details['allocated'] ?? '—' ); ?></td>
			<td class="wp-sam-col-status">
				<?php
				if ( in_array( '', $asn_surfaces, true ) ) {
					esc_html_e( 'On every surface', 'vcns-security-automation-manager' );
				} elseif ( ! empty( $asn_surfaces ) ) {
					echo esc_html( implode( ', ', array_map( 'ucfirst', $asn_surfaces ) ) );
				} else {
					esc_html_e( 'No', 'vcns-security-automation-manager' );
				}
				?>
			</td>
			<td class="wp-sam-col-actions">
				<?php if ( ! in_array( '', $asn_surfaces, true ) ) : ?>
				<a class="button button-small" href="<?php echo esc_url( $asn_block_url ); ?>">
					<?php
					/* translators: %s: AS number, e.g. AS15169 */
					echo esc_html( sprintf( __( 'Block %s', 'vcns-security-automation-manager' ), $asn_label ) );
					?>
				</a>
				<?php endif; ?>
				<?php if ( ! empty( $asn_rules ) ) : ?>
				<a class="button button-small" href="<?php echo esc_url( add_query_arg( 'subtab', 'network-rules', $ni_base_url ) ); ?>"><?php esc_html_e( 'Network Rules', 'vcns-security-automation-manager' ); ?></a>
				<?php endif; ?>
			</td>
		</tr>
	</tbody>
</table>
</div>

<p class="description">
	<?php
	/* translators: %s: AS number, e.g. AS15169 */
	echo esc_html( sprintf( __( 'Every address range %s routes, and the networks it connects to, are public. See them on:', 'vcns-security-automation-manager' ), $asn_label ) );
	?>
	<a href="<?php echo esc_url( 'https://bgp.he.net/' . $asn_label . '#_prefixes' ); ?>" target="_blank" rel="noopener noreferrer"><?php esc_html_e( 'Hurricane Electric BGP Toolkit', 'vcns-security-automation-manager' ); ?></a>
	&middot;
	<a href="<?php echo esc_url( 'https://stat.ripe.net/resource/' . $asn_label ); ?>" target="_blank" rel="noopener noreferrer"><?php esc_html_e( 'RIPEstat', 'vcns-security-automation-manager' ); ?></a>
</p>

<h4 style="margin:1.5em 0 0.25em">
	<?php
	/* translators: %s: AS number, e.g. AS15169 */
	echo esc_html( sprintf( __( 'Addresses seen from %s', 'vcns-security-automation-manager' ), $asn_label ) );
	?>
</h4>
<p class="description" style="margin-top:0">
	<?php esc_html_e( 'An address is listed here once a detector has looked at one of its requests, so these are this network\'s visitors that drew attention, not all of them. Most recent first; up to 50.', 'vcns-security-automation-manager' ); ?>
</p>

<div class="wp-sam-table-wrap">
<table class="widefat striped wp-sam-table wp-sam-asn-addresses-table" style="margin-top:0.5em">
	<thead>
		<tr>
			<th class="wp-sam-col-technical"><?php esc_html_e( 'IP', 'vcns-security-automation-manager' ); ?></th>
			<th class="wp-sam-col-count"><?php esc_html_e( 'Times seen', 'vcns-security-automation-manager' ); ?></th>
			<th class="wp-sam-col-datetime"><?php esc_html_e( 'Last seen', 'vcns-security-automation-manager' ); ?></th>
			<th class="wp-sam-col-actions"><?php esc_html_e( 'Actions', 'vcns-security-automation-manager' ); ?></th>
		</tr>
	</thead>
	<tbody>
	<?php foreach ( $asn_addresses as $asn_address ) : ?>
		<tr>
			<td class="wp-sam-col-technical"><code><?php echo esc_html( $asn_address['ip'] ); ?></code></td>
			<td class="wp-sam-col-count"><?php echo esc_html( number_format( $asn_address['times_seen'] ) ); ?></td>
			<td class="wp-sam-col-datetime"><?php echo esc_html( $asn_address['last_seen_at'] ); ?></td>
			<td class="wp-sam-col-actions">
				<?php if ( $asn_ip_blocked( $asn_address['ip'] ) ) : ?>
				<span class="description"><?php esc_html_e( 'IP blocked', 'vcns-security-automation-manager' ); ?></span>
				<?php else : ?>
				<a class="button button-small" href="<?php echo esc_url( add_query_arg( array( 'cidr' => $asn_address['ip'] ), $asn_ip_rule_url ) . '#wp-sam-ip-rule-add' ); ?>"><?php esc_html_e( 'Block IP', 'vcns-security-automation-manager' ); ?></a>
				<?php endif; ?>
			</td>
		</tr>
	<?php endforeach; ?>
	<?php if ( empty( $asn_addresses ) ) : ?>
		<tr>
			<td colspan="4"><p><?php esc_html_e( 'None recorded yet.', 'vcns-security-automation-manager' ); ?></p></td>
		</tr>
	<?php endif; ?>
	</tbody>
</table>
</div>
