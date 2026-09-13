<?php
/**
 * Recommendation rule: an issued production TLS certificate has expired or
 * is within its renewal window (Phase 4F, rule batch 1).
 *
 * Deliberately scoped to renewal only, not initial issuance -- a site with
 * domains configured but nothing issued yet is already covered by Settings/
 * Overview's own Getting Started step 5 ("Issue a free TLS certificate").
 * Firing this rule too in that case would just repeat that nudge under a
 * different name.
 *
 * Dismissible: a "quiet live condition" with no natural underlying per-item
 * record of its own (see Recommendation_Dismissal_Store's docblock) -- an
 * administrator managing this domain's TLS elsewhere (host/CDN) may
 * deliberately want to silence this until something actually changes.
 */

declare( strict_types=1 );

namespace WP_SAM\Intelligence;

use WP_SAM\Certificates\Certificate_Store;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Recommendation_Rule_Certificate_Renewal implements Recommendation_Rule {

	public function id(): string {
		return 'certificate_renewal_due';
	}

	/** @return array<int, array<string, mixed>> */
	public function evaluate(): array {
		$store  = new Certificate_Store();
		$config = $store->get_config();

		if ( empty( array_filter( (array) $config['domains'] ) ) ) {
			return array(); // Not configured -- Getting Started covers initial setup.
		}

		$latest = $store->latest_certificate( 'production' );
		if ( null === $latest || empty( $latest['not_after'] ) ) {
			return array(); // Nothing issued yet -- Getting Started covers initial issuance, not renewal.
		}

		if ( ! $store->renewal_due( 30 ) ) {
			return array();
		}

		$not_after = strtotime( (string) $latest['not_after'] . ' UTC' );
		$expired   = false !== $not_after && $not_after < time();

		return array(
			array(
				'key'                 => 'certificate_renewal_due',
				'layer'               => __( 'Layer 5: Transport & Certificate Trust', 'vcns-security-automation-manager' ),
				'pillar'              => __( 'Certificates', 'vcns-security-automation-manager' ),
				'surface'             => null,
				'observed'            => $expired
					? __( 'The issued TLS certificate has already expired.', 'vcns-security-automation-manager' )
					: sprintf(
						/* translators: %s: certificate expiry date/time (UTC) */
						__( 'The issued TLS certificate expires %s UTC, within the renewal window.', 'vcns-security-automation-manager' ),
						$latest['not_after']
					),
				'why_it_matters'      => __( 'Once a certificate expires, every browser shows visitors a hard warning page before any of this plugin\'s other protections get a chance to matter.', 'vcns-security-automation-manager' ),
				'confidence'          => 'high',
				'risk'                => $expired ? 'critical' : 'high',
				'evidence'            => array(
					'not_after'   => $latest['not_after'],
					'environment' => $latest['environment'] ?? 'production',
				),
				'recommended_action'  => __( 'Renew the certificate from the Certificates page.', 'vcns-security-automation-manager' ),
				'alternative_action'  => __( 'If this domain now gets HTTPS from your host or CDN instead, remove the configured domains here so this plugin stops tracking it.', 'vcns-security-automation-manager' ),
				'automation_eligible' => false,
				'rollback_position'   => __( 'Issuing a new certificate does not remove or invalidate the current one before it expires.', 'vcns-security-automation-manager' ),
				'evidence_changed_at' => (string) $latest['updated_at'],
				'cta_url'             => admin_url( 'admin.php?page=security-automation-manager-certificates' ),
				'dismissible'         => true,
			),
		);
	}
}
