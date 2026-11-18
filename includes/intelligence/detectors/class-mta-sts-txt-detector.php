<?php
/**
 * Recognises when a source fetches this domain's MTA-STS policy, the
 * same observation-only visit signal as Security_Txt_Detector and the
 * other well-known-file detectors. The requests come from mail servers
 * checking how to deliver to this domain, and only reach this site when
 * mta-sts.<domain> points here (see Mta_Sts_Policy), so they are
 * recorded for correlation, never treated as evidence of anything.
 */

declare( strict_types=1 );

namespace WP_SAM\Intelligence\Detectors;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Mta_Sts_Txt_Detector extends Pattern_Detector {

	public function id(): string {
		return 'mta-sts-txt-visit';
	}

	public function family(): string {
		return 'mta-sts-txt-visit';
	}

	public function description(): string {
		return __( 'Notes when a mail server fetches your MTA-STS policy -- recorded for correlation only.', 'vcns-security-automation-manager' );
	}

	public function applicable_surfaces(): array {
		return array();
	}

	protected function subject( array $context ): string {
		return (string) ( $context['path'] ?? '' );
	}

	protected function rules(): array {
		return array(
			array(
				'id'          => 'MTASTS-001',
				'pattern'     => '#^/\.well-known/mta-sts\.txt$#i',
				'severity'    => 'low',
				'confidence'  => 0.95,
				'description' => 'Source fetched the MTA-STS policy -- normally a mail server checking how to deliver to this domain; recorded for correlation only.',
			),
		);
	}
}
