<?php
/**
 * Recommendation rule: a pinned third-party script/stylesheet no longer
 * matches its approved Subresource Integrity hash -- the vendor changed the
 * file, so browsers enforcing the markup's integrity attribute are refusing
 * to load it.
 *
 * One recommendation per drifted inventory row (Security\
 * Pinned_Dependency_Checker records the drift). High risk: unlike most
 * drift, this one is already breaking the site for real visitors.
 *
 * Not dismissible: acting on it means re-approving the new hash or
 * reclassifying the row under Decide → Dependency Classification, either of
 * which clears the drift and drops the recommendation -- no separate
 * dismissal storage needed (see Recommendation_Dismissal_Store's docblock).
 */

declare( strict_types=1 );

namespace WP_SAM\Intelligence;

use WP_SAM\Security\Known_Vendor_Profiles;
use WP_SAM\Security\Pinned_Dependency_Checker;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Recommendation_Rule_Dependency_Hash_Drift implements Recommendation_Rule {

	public const KEY_PREFIX = 'dependency_sri_drift_';

	public function id(): string {
		return 'dependency_sri_drift';
	}

	/** @return array<int, array<string, mixed>> */
	public function evaluate(): array {
		$recommendations = array();

		foreach ( Pinned_Dependency_Checker::drifted_rows() as $row ) {
			$origin        = (string) $row['origin'];
			$resource_type = (string) $row['resource_type'];
			$url           = '' !== trim( (string) ( $row['pinned_url'] ?? '' ) ) ? (string) $row['pinned_url'] : (string) ( $row['last_seen_url'] ?? '' );
			$vendor        = Known_Vendor_Profiles::match( $origin, (string) ( $row['last_seen_url'] ?? '' ), $resource_type );

			$recommended = null !== $vendor
				? sprintf(
					/* translators: %s: vendor name, e.g. "Google Tag Manager" */
					__( '%s changes this file routinely, so pinning it by hash will keep breaking. Under Decide → Dependency Classification, use "Allow by host instead" for this origin, and remove the integrity attribute from the markup that loads it.', 'vcns-security-automation-manager' ),
					$vendor['vendor']
				)
				: __( 'Check the new file under Decide → Dependency Classification. If the change is expected, use "Re-approve new hash" and update the integrity attribute in the theme or plugin markup that loads it to the new value.', 'vcns-security-automation-manager' );

			$alternative = null !== $vendor
				? __( 'If you need this exact version pinned, re-approve the new hash there instead, and update the integrity attribute in the markup to match.', 'vcns-security-automation-manager' )
				: __( 'If this provider changes the file regularly, use "Allow by host instead" there (Approved -- mutable provider) rather than pinning a hash.', 'vcns-security-automation-manager' );

			$recommendations[] = array(
				'key'                 => self::KEY_PREFIX . (int) $row['id'],
				'layer'               => __( 'Layer 4: Browser Security Policies', 'vcns-security-automation-manager' ),
				'pillar'              => __( 'External Scripts', 'vcns-security-automation-manager' ),
				'surface'             => (string) $row['surface'],
				'observed'            => sprintf(
					/* translators: 1: "script" or "style", 2: origin, 3: surface */
					__( 'Pinned script hash has drifted: the pinned %1$s from %2$s (%3$s) no longer matches its approved hash.', 'vcns-security-automation-manager' ),
					'style' === $resource_type ? __( 'stylesheet', 'vcns-security-automation-manager' ) : __( 'script', 'vcns-security-automation-manager' ),
					$origin,
					(string) $row['surface']
				),
				'why_it_matters'      => __( 'Browsers refuse to run a file whose content no longer matches its integrity hash, so whatever this file provides is probably already broken for visitors.', 'vcns-security-automation-manager' ),
				'confidence'          => 'high',
				'risk'                => 'high',
				'evidence'            => array(
					'url'           => $url,
					'pinned_sri'    => (string) $row['expected_sri'],
					'observed_sri'  => (string) $row['drift_observed_sri'],
					'first_seen_at' => (string) $row['drift_detected_at'],
					'known_vendor'  => null !== $vendor ? $vendor['vendor'] : '',
				),
				'recommended_action'  => $recommended,
				'alternative_action'  => $alternative,
				'automation_eligible' => false,
				'rollback_position'   => __( 'Re-approving only changes the hash SAM compares against; the previous hash stays in the audit log if you need to restore it.', 'vcns-security-automation-manager' ),
				'evidence_changed_at' => '' !== (string) ( $row['integrity_checked_at'] ?? '' ) ? (string) $row['integrity_checked_at'] : (string) $row['drift_detected_at'],
				'cta_url'             => admin_url( 'admin.php?page=security-automation-manager-scripts&tab=external' ),
				'dismissible'         => false,
			);
		}

		return $recommendations;
	}
}
