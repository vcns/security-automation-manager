<?php
/**
 * Admin partial: what else MTA-STS needs besides the policy file, shown
 * under the MTA-STS.txt editor on Control → Traffic Controls → Network
 * Intelligence → Well-Known Files.
 *
 * Mail servers only use the policy once all of these are in place: the
 * policy address reaches this site with a certificate covering it, and a
 * _mta-sts TXT record carries the id of the version being served. TLS
 * reports are optional, but they are how an administrator finds out
 * whether switching to enforce would break delivery. This plugin serves
 * the file and looks each record up; the records themselves are added
 * wherever the domain's DNS is managed.
 *
 * Rendered by well-known-file-editor.php.
 *
 * @var array{content:string, saved_at:string, saved_by:int, check:string}|null $wk_saved
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use WP_SAM\Certificates\Certificate_Store;
use WP_SAM\Intelligence\Mail_Dns;
use WP_SAM\Intelligence\Mta_Sts_Policy;
use WP_SAM\Intelligence\Well_Known_File_Store;

$mta_domain  = Mta_Sts_Policy::domain();
$mta_host    = Mta_Sts_Policy::host();
$mta_mx      = Mail_Dns::mx_hosts( $mta_domain );
$mta_sts     = Mail_Dns::sts_record( $mta_domain );
$mta_tls_rpt = Mail_Dns::tls_rpt_record( $mta_domain );
$mta_policy  = null !== $wk_saved ? Mta_Sts_Policy::parse( $wk_saved['content'] ) : null;
$mta_id      = null !== $wk_saved ? Mta_Sts_Policy::id( $wk_saved['content'] ) : null;

// The certificate this plugin issues, when it issues one: read straight
// from the stored configuration, which keeps its domains unsealed.
$mta_cert_config  = get_option( Certificate_Store::CONFIG_OPTION, array() );
$mta_cert_domains = array_map( 'strtolower', array_map( 'strval', (array) ( is_array( $mta_cert_config ) ? ( $mta_cert_config['domains'] ?? array() ) : array() ) ) );

$mta_unknown = __( 'This server couldn\'t look up DNS, so this plugin can\'t tell.', 'vcns-security-automation-manager' );

// Step 1: the policy address.
$mta_address_status = array(
	Well_Known_File_Store::CHECK_SERVED      => __( 'Mail servers get the saved version.', 'vcns-security-automation-manager' ),
	Well_Known_File_Store::CHECK_NOT_SERVED  => __( 'Answers with something else.', 'vcns-security-automation-manager' ),
	Well_Known_File_Store::CHECK_UNREACHABLE => __( 'Couldn\'t be fetched.', 'vcns-security-automation-manager' ),
)[ $wk_saved['check'] ?? '' ] ?? __( 'Save the policy to check.', 'vcns-security-automation-manager' );

// Step 2: the _mta-sts TXT record.
switch ( $mta_sts['status'] ) {
	case Mail_Dns::UNKNOWN:
		$mta_sts_status = $mta_unknown;
		break;
	case Mail_Dns::MISSING:
		$mta_sts_status = __( 'Not found. Until it exists, mail servers don\'t look for the policy.', 'vcns-security-automation-manager' );
		break;
	case Mail_Dns::MULTIPLE:
		$mta_sts_status = __( 'There is more than one v=STSv1 record, so mail servers ignore all of them. Keep one.', 'vcns-security-automation-manager' );
		break;
	case Mail_Dns::INVALID:
		$mta_sts_status = __( 'Found, but its id isn\'t 1 to 32 letters and digits, so mail servers ignore it.', 'vcns-security-automation-manager' );
		break;
	default:
		if ( null === $mta_id ) {
			/* translators: %s: the id in the DNS record */
			$mta_sts_status = sprintf( __( 'Found, with id %s.', 'vcns-security-automation-manager' ), $mta_sts['id'] );
		} elseif ( $mta_sts['id'] === $mta_id ) {
			$mta_sts_status = __( 'Matches the saved version.', 'vcns-security-automation-manager' );
		} else {
			/* translators: 1: the id in the DNS record, 2: the saved version's id */
			$mta_sts_status = sprintf( __( 'Found with id %1$s. Change it to %2$s so mail servers fetch the saved version; until then, any that cached an earlier one keep using it.', 'vcns-security-automation-manager' ), $mta_sts['id'], $mta_id );
		}
}

// Step 3: which of the domain's mail servers the saved policy covers.
$mta_uncovered = null !== $mta_policy && ! empty( $mta_mx ) ? Mta_Sts_Policy::uncovered( $mta_mx, $mta_policy['mx'] ) : array();
?>

<h4><?php esc_html_e( 'Mail server setup', 'vcns-security-automation-manager' ); ?></h4>
<p class="description">
	<?php esc_html_e( 'Mail servers only use this policy once each step below is in place. This plugin serves the file; the DNS records are added wherever this domain\'s DNS is managed, and this table looks them up each time it opens.', 'vcns-security-automation-manager' ); ?>
</p>

<div class="wp-sam-table-wrap">
<table class="widefat striped wp-sam-table wp-sam-mta-sts-setup">
	<thead>
		<tr>
			<th class="wp-sam-col-primary"><?php esc_html_e( 'Step', 'vcns-security-automation-manager' ); ?></th>
			<th><?php esc_html_e( 'What it needs', 'vcns-security-automation-manager' ); ?></th>
			<th class="wp-sam-col-status"><?php esc_html_e( 'Status', 'vcns-security-automation-manager' ); ?></th>
		</tr>
	</thead>
	<tbody>
		<tr>
			<td class="wp-sam-col-primary"><?php esc_html_e( 'Policy address', 'vcns-security-automation-manager' ); ?></td>
			<td>
				<?php
				/* translators: %s: the policy host, e.g. mta-sts.example.com */
				echo esc_html( sprintf( __( 'A DNS record for %s pointing at this server, a web server that answers that name with this site, and a certificate that covers it. Mail servers don\'t follow redirects there.', 'vcns-security-automation-manager' ), $mta_host ) );
				?>
				<?php if ( array() !== $mta_cert_domains ) : ?>
				<br /><span class="description">
					<?php if ( in_array( $mta_host, $mta_cert_domains, true ) || in_array( '*.' . $mta_domain, $mta_cert_domains, true ) ) : ?>
						<?php esc_html_e( 'The certificate this plugin is set up to issue covers it.', 'vcns-security-automation-manager' ); ?>
					<?php else : ?>
						<?php
						/* translators: %s: the policy host, e.g. mta-sts.example.com */
						echo esc_html( sprintf( __( 'The certificate this plugin is set up to issue doesn\'t cover %s yet.', 'vcns-security-automation-manager' ), $mta_host ) );
						?>
						<a href="<?php echo esc_url( admin_url( 'admin.php?page=security-automation-manager-certificates&tab=configuration' ) ); ?>"><?php esc_html_e( 'Open Control → Certificates → Configuration', 'vcns-security-automation-manager' ); ?></a>
					<?php endif; ?>
				</span>
				<?php endif; ?>
			</td>
			<td class="wp-sam-col-status"><?php echo esc_html( $mta_address_status ); ?></td>
		</tr>
		<tr>
			<td class="wp-sam-col-primary"><?php esc_html_e( 'MTA-STS DNS record', 'vcns-security-automation-manager' ); ?></td>
			<td>
				<?php esc_html_e( 'A TXT record named', 'vcns-security-automation-manager' ); ?>
				<code><?php echo esc_html( '_mta-sts.' . $mta_domain ); ?></code>
				<?php if ( null !== $wk_saved ) : ?>
					<?php esc_html_e( 'with the value', 'vcns-security-automation-manager' ); ?>
					<code><?php echo esc_html( Mta_Sts_Policy::dns_record( $wk_saved['content'] ) ); ?></code>
					<br /><span class="description"><?php esc_html_e( 'Each version of the policy has its own id, so change the record whenever you save a change here. That is how mail servers know to fetch it again.', 'vcns-security-automation-manager' ); ?></span>
				<?php else : ?>
					<?php esc_html_e( 'with the id of the version being served. Save the policy to get its id.', 'vcns-security-automation-manager' ); ?>
				<?php endif; ?>
			</td>
			<td class="wp-sam-col-status"><?php echo esc_html( $mta_sts_status ); ?></td>
		</tr>
		<tr>
			<td class="wp-sam-col-primary"><?php esc_html_e( 'Mail servers', 'vcns-security-automation-manager' ); ?></td>
			<td>
				<?php if ( null === $mta_mx ) : ?>
					<?php esc_html_e( 'Every mail server this domain\'s MX records name must match an mx line.', 'vcns-security-automation-manager' ); ?>
				<?php elseif ( array() === $mta_mx ) : ?>
					<?php esc_html_e( 'This domain has no MX records, so it doesn\'t receive email at its own address and MTA-STS has nothing to protect.', 'vcns-security-automation-manager' ); ?>
				<?php else : ?>
					<?php esc_html_e( 'Every mail server this domain\'s MX records name must match an mx line:', 'vcns-security-automation-manager' ); ?>
					<?php foreach ( $mta_mx as $mta_mx_host ) : ?>
					<br /><code><?php echo esc_html( $mta_mx_host ); ?></code>
						<?php if ( in_array( $mta_mx_host, $mta_uncovered, true ) ) : ?>
						<strong><?php esc_html_e( 'not matched by the saved policy', 'vcns-security-automation-manager' ); ?></strong>
						<?php endif; ?>
					<?php endforeach; ?>
				<?php endif; ?>
			</td>
			<td class="wp-sam-col-status">
				<?php
				if ( null === $mta_mx ) {
					echo esc_html( $mta_unknown );
				} elseif ( null === $mta_policy || array() === $mta_mx ) {
					echo '&mdash;';
				} elseif ( array() === $mta_uncovered ) {
					esc_html_e( 'The saved policy matches all of them.', 'vcns-security-automation-manager' );
				} elseif ( 'enforce' === $mta_policy['mode'] ) {
					esc_html_e( 'Mail servers that follow the policy won\'t deliver to the ones it doesn\'t match.', 'vcns-security-automation-manager' );
				} else {
					esc_html_e( 'Fine while testing, but enforce mode would stop delivery to the ones it doesn\'t match.', 'vcns-security-automation-manager' );
				}
				?>
			</td>
		</tr>
		<tr>
			<td class="wp-sam-col-primary"><?php esc_html_e( 'TLS reports (optional)', 'vcns-security-automation-manager' ); ?></td>
			<td>
				<?php esc_html_e( 'A TXT record named', 'vcns-security-automation-manager' ); ?>
				<code><?php echo esc_html( '_smtp._tls.' . $mta_domain ); ?></code>
				<?php esc_html_e( 'such as', 'vcns-security-automation-manager' ); ?>
				<code><?php echo esc_html( Mta_Sts_Policy::tls_rpt_suggestion() ); ?></code>
				<br /><span class="description"><?php esc_html_e( 'Large mail providers then send a daily report of connections to this domain that failed. Check them in testing mode before switching to enforce.', 'vcns-security-automation-manager' ); ?></span>
			</td>
			<td class="wp-sam-col-status">
				<?php
				if ( Mail_Dns::UNKNOWN === $mta_tls_rpt['status'] ) {
					echo esc_html( $mta_unknown );
				} elseif ( Mail_Dns::FOUND === $mta_tls_rpt['status'] ) {
					/* translators: %s: the TLS reporting record's value */
					echo esc_html( sprintf( __( 'Found: %s', 'vcns-security-automation-manager' ), (string) $mta_tls_rpt['record'] ) );
				} elseif ( Mail_Dns::MULTIPLE === $mta_tls_rpt['status'] ) {
					esc_html_e( 'There is more than one v=TLSRPTv1 record, so mail servers ignore all of them. Keep one.', 'vcns-security-automation-manager' );
				} else {
					esc_html_e( 'Not found.', 'vcns-security-automation-manager' );
				}
				?>
			</td>
		</tr>
	</tbody>
</table>
</div>
