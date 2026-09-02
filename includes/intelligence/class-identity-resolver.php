<?php
/**
 * Resolves a request's claimed identity against the Scanner_Vendor_Store
 * catalogue (Phase 3D, .roadmap/phase3_early_plan.md §8 Identity
 * Verification, §31 "Identity Resolver" / "Network Intelligence Resolver").
 *
 * resolve() is the cheap, synchronous, per-request path Request_Observer
 * calls on every hit: a user-agent substring match against each vendor's
 * ua_pattern, plus an in-memory CIDR check if the matched vendor has
 * published ranges on file. No network I/O -- see §33 Performance
 * Requirements ("avoid repeated external lookups during requests").
 *
 * verify_fcrdns() is the expensive, deliberately NOT-automatic path: real
 * DNS lookups (reverse then forward-confirm), only ever triggered by an
 * explicit administrator action against one specific event, never from the
 * request-observation hot path.
 *
 * Whatever resolve() returns is only ever a *recognition* signal
 * (known_commercial_scanner / known_research_scanner / known_crawler /
 * unknown) -- it is Scanner_Identity_Store's job, not this class's, to make
 * sure recognition never silently becomes authorisation.
 */

declare( strict_types=1 );

namespace WP_SAM\Intelligence;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Identity_Resolver {

	private Scanner_Vendor_Store $vendors;

	/** @var array<int, array<string, mixed>>|null Per-request cache -- resolve() may run once per hit, no reason to re-query the catalogue. */
	private ?array $vendor_cache = null;

	/** @var callable(string):(string|false) Real gethostbyaddr() by default; injectable so tests never make a real DNS call. */
	private $reverse_lookup;

	/** @var callable(string):string Real gethostbyname() by default; injectable so tests never make a real DNS call. */
	private $forward_lookup;

	public function __construct( Scanner_Vendor_Store $vendors, ?callable $reverse_lookup = null, ?callable $forward_lookup = null ) {
		$this->vendors        = $vendors;
		$this->reverse_lookup = $reverse_lookup ?? static fn ( string $ip ) => @gethostbyaddr( $ip ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- gethostbyaddr() emits a warning on lookup failure; failure is a normal, expected outcome here.
		$this->forward_lookup = $forward_lookup ?? static fn ( string $hostname ) => @gethostbyname( $hostname ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- same rationale.
	}

	/**
	 * @return array{claimed_identity:string, vendor_key:string, verification_state:string, network_match:?bool}
	 */
	public function resolve( string $ip, string $user_agent ): array {
		if ( '' === trim( $user_agent ) ) {
			return array(
				'claimed_identity'   => '',
				'vendor_key'         => '',
				'verification_state' => 'unknown',
				'network_match'      => null,
			);
		}

		foreach ( $this->vendor_catalogue() as $vendor ) {
			$pattern = (string) ( $vendor['ua_pattern'] ?? '' );
			if ( '' === $pattern || false === stripos( $user_agent, $pattern ) ) {
				continue;
			}

			$cidr_ranges   = is_array( $vendor['cidr_ranges'] ?? null ) ? $vendor['cidr_ranges'] : array();
			$network_match = ! empty( $cidr_ranges ) ? Cidr_Matcher::ip_in_any_cidr( $ip, $cidr_ranges ) : null;

			return array(
				'claimed_identity'   => (string) $vendor['vendor_name'],
				'vendor_key'         => (string) $vendor['vendor_key'],
				'verification_state' => $this->state_for_category( (string) $vendor['category'] ),
				'network_match'      => $network_match,
			);
		}

		return array(
			'claimed_identity'   => '',
			'vendor_key'         => '',
			'verification_state' => 'unknown',
			'network_match'      => null,
		);
	}

	/**
	 * On-demand forward-confirmed reverse DNS check (§8: "reverse-DNS
	 * verification method", "forward-confirmed reverse-DNS"). Never called
	 * from resolve() or the request-observation path -- only from an
	 * explicit admin action against one already-recorded identity.
	 *
	 * @return array{hostname:string, suffix_match:bool, forward_confirmed:bool}
	 */
	public function verify_fcrdns( string $ip, string $vendor_key ): array {
		$vendor = $this->vendors->get( $vendor_key );
		$result = array(
			'hostname'          => '',
			'suffix_match'      => false,
			'forward_confirmed' => false,
		);

		if ( null === $vendor || '' === $ip ) {
			return $result;
		}

		$hostname = ( $this->reverse_lookup )( $ip );
		if ( false === $hostname || $hostname === $ip ) {
			return $result;
		}
		$result['hostname'] = $hostname;

		$suffixes = is_array( $vendor['rdns_suffixes'] ?? null ) ? $vendor['rdns_suffixes'] : array();
		foreach ( $suffixes as $suffix ) {
			$suffix = (string) $suffix;
			if ( '' !== $suffix && ( $hostname === $suffix || str_ends_with( $hostname, '.' . $suffix ) ) ) {
				$result['suffix_match'] = true;
				break;
			}
		}
		if ( ! $result['suffix_match'] ) {
			return $result;
		}

		$result['forward_confirmed'] = ( ( $this->forward_lookup )( $hostname ) === $ip );

		return $result;
	}

	private function state_for_category( string $category ): string {
		switch ( $category ) {
			case 'known_commercial_scanner':
				return 'known_commercial_scanner';
			case 'known_research_scanner':
				return 'known_research_scanner';
			case 'known_crawler':
				return 'known_crawler';
			default:
				return 'unknown';
		}
	}

	/** @return array<int, array<string, mixed>> */
	private function vendor_catalogue(): array {
		if ( null === $this->vendor_cache ) {
			$this->vendor_cache = $this->vendors->all();
		}
		return $this->vendor_cache;
	}
}
