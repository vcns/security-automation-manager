<?php
/**
 * Caches this domain's MTA-STS policy as mail servers see it, for the
 * MTA-STS.txt row on Control → Traffic Controls → Network Intelligence →
 * Well-Known Files. Same daily refresh as the other well-known files'
 * stores (see Robots_Rules_Store for the shared reasoning), with two
 * differences from them:
 *
 * - It fetches https://mta-sts.<domain>/.well-known/mta-sts.txt the way
 *   RFC 8461 §3.3 says mail servers do (Mta_Sts_Policy::fetch()): no
 *   redirect followed, and the response must be text/plain.
 * - A policy that can't be fetched only counts as a failure when this
 *   domain's _mta-sts DNS record says it has one. Most domains publish no
 *   policy and have no mta-sts host at all; for them an unreachable host
 *   is the normal answer, recorded as absent, so the daily check doesn't
 *   raise a warning every day. When the record does exist, mail servers
 *   look for the policy, and failing to fetch it is a real problem.
 */

declare( strict_types=1 );

namespace WP_SAM\Intelligence;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Mta_Sts_Txt_Store {

	private const OPTION_FIELDS    = 'wp_sam_mta_sts_txt_fields';
	private const OPTION_REFRESHED = 'wp_sam_mta_sts_txt_refreshed_at';
	private const OPTION_STATUS    = 'wp_sam_mta_sts_txt_last_fetch_status';

	/** @var callable(string):(array|\WP_Error) Mta_Sts_Policy::fetch() by default; injectable so tests never make a real HTTP call. */
	private $http_get;

	public function __construct( ?callable $http_get = null ) {
		$this->http_get = $http_get ?? array( Mta_Sts_Policy::class, 'fetch' );
	}

	/** True once a fetch has succeeded, whatever the policy says. */
	public function is_present(): bool {
		return 'success' === $this->last_fetch_status();
	}

	/**
	 * The policy's fields as last fetched (Mta_Sts_Policy::parse()), plus
	 * what the _mta-sts DNS record said at the time.
	 *
	 * @return array{version:?string, mode:?string, max_age:?string, mx:array<int,string>, dns_status:string, dns_id:?string}|array{}
	 */
	public function fields(): array {
		$stored = get_option( self::OPTION_FIELDS, array() );
		return is_array( $stored ) ? $stored : array();
	}

	public function last_refreshed_at(): ?string {
		$value = get_option( self::OPTION_REFRESHED, '' );
		return '' !== $value ? (string) $value : null;
	}

	public function last_fetch_status(): string {
		return (string) get_option( self::OPTION_STATUS, '' );
	}

	/**
	 * Fetches this domain's policy and replaces the cached fields on
	 * success. Never touches them on failure.
	 *
	 * @return array{status:string, count:int, message:string}
	 */
	public function refresh(): array {
		$domain = Mta_Sts_Policy::domain();
		if ( '' === $domain ) {
			return $this->record_absent( __( 'This site\'s address isn\'t a domain name, so it has no MTA-STS policy.', 'vcns-security-automation-manager' ) );
		}

		$dns        = Mail_Dns::sts_record( $domain );
		$advertised = in_array( $dns['status'], array( Mail_Dns::FOUND, Mail_Dns::MULTIPLE, Mail_Dns::INVALID ), true );
		$response   = ( $this->http_get )( Mta_Sts_Policy::url() );
		$reason     = Mta_Sts_Policy::unusable_reason( $response );

		if ( null !== $reason ) {
			if ( ! $advertised ) {
				/* translators: 1: this site's domain, 2: why the policy address couldn't be used, e.g. "returned HTTP 404" */
				return $this->record_absent( sprintf( __( 'No MTA-STS policy for %1$s: there is no _mta-sts DNS record, and the policy address %2$s.', 'vcns-security-automation-manager' ), $domain, $reason ) );
			}
			/* translators: 1: this site's domain, 2: why the policy address couldn't be used, e.g. "returned HTTP 404" */
			return $this->record_failure( sprintf( __( 'The _mta-sts DNS record says %1$s uses MTA-STS, but its policy address %2$s.', 'vcns-security-automation-manager' ), $domain, $reason ) );
		}

		$fields = Mta_Sts_Policy::parse( (string) wp_remote_retrieve_body( $response ) ) + array(
			'dns_status' => $dns['status'],
			'dns_id'     => $dns['id'],
		);

		update_option( self::OPTION_FIELDS, $fields, false );
		update_option( self::OPTION_REFRESHED, current_time( 'mysql', true ), false );
		update_option( self::OPTION_STATUS, 'success', false );

		return array(
			'status'  => 'refreshed',
			'count'   => count( $fields['mx'] ),
			/* translators: %s: the policy's mode, e.g. enforce */
			'message' => sprintf( __( 'Refreshed the MTA-STS policy (mode: %s).', 'vcns-security-automation-manager' ), $fields['mode'] ?? '?' ),
		);
	}

	/** @return array{status:string, count:int, message:string} */
	private function record_absent( string $message ): array {
		delete_option( self::OPTION_FIELDS );
		update_option( self::OPTION_REFRESHED, current_time( 'mysql', true ), false );
		update_option( self::OPTION_STATUS, 'absent', false );

		return array(
			'status'  => 'absent',
			'count'   => 0,
			'message' => $message,
		);
	}

	/** @return array{status:string, count:int, message:string} */
	private function record_failure( string $message ): array {
		update_option( self::OPTION_STATUS, 'failed', false );

		return array(
			'status'  => 'failed',
			'count'   => count( $this->fields()['mx'] ?? array() ),
			'message' => $message,
		);
	}
}
