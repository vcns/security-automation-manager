<?php
/**
 * RFC 2136 dynamic-update driver with TSIG (RFC 8945) signing.
 *
 * Speaks the raw DNS wire protocol over TCP to any authoritative server
 * that accepts TSIG-signed UPDATE messages -- BIND, Knot, PowerDNS,
 * Windows Server DNS, and most other self-hosted or enterprise DNS. This is
 * the standards-based answer for infrastructure that has no vendor REST API.
 *
 * Example BIND config:
 *   key "wp-sam" { algorithm hmac-sha256; secret "<base64>"; };
 *   zone "example.com" { ... update-policy { grant wp-sam name _acme-challenge.example.com. TXT; }; };
 */

declare( strict_types=1 );

namespace WP_SAM\Certificates\Providers;

use WP_SAM\Certificates\Dns_Provider;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class Provider_Rfc2136 extends Dns_Provider {

	private const ALGORITHMS = array(
		'hmac-sha256' => array( 'hmac-sha256.', 'sha256' ),
		'hmac-sha512' => array( 'hmac-sha512.', 'sha512' ),
		'hmac-sha1'   => array( 'hmac-sha1.', 'sha1' ),
		'hmac-md5'    => array( 'hmac-md5.sig-alg.reg.int.', 'md5' ),
	);

	public static function label(): string {
		return 'RFC 2136 dynamic update (BIND, Knot, Windows DNS, ...)';
	}

	public static function fields(): array {
		return array(
			'server'    => array(
				'label'       => __( 'DNS server (host or host:port; port defaults to 53)', 'security-automation-manager' ),
				'secret'      => false,
				'placeholder' => 'ns1.example.com',
			),
			'zone'      => array(
				'label'       => __( 'Zone accepting updates', 'security-automation-manager' ),
				'secret'      => false,
				'placeholder' => 'example.com',
			),
			'key_name'  => array(
				'label'       => __( 'TSIG key name', 'security-automation-manager' ),
				'secret'      => false,
				'placeholder' => 'wp-sam',
			),
			'secret'    => array(
				'label' => __( 'TSIG secret (base64)', 'security-automation-manager' ),
			),
			'algorithm' => array(
				'label'       => __( 'TSIG algorithm (hmac-sha256, hmac-sha512, hmac-sha1, hmac-md5)', 'security-automation-manager' ),
				'secret'      => false,
				'placeholder' => 'hmac-sha256',
			),
		);
	}

	public function create_txt_record( string $fqdn, string $value ): void {
		$this->send_update( $fqdn, $value, true );
	}

	public function delete_txt_record( string $fqdn, string $value ): void {
		$this->send_update( $fqdn, $value, false );
	}

	// ── Wire protocol ─────────────────────────────────────────────────────────

	private function send_update( string $fqdn, string $value, bool $add ): void {
		$zone = rtrim( trim( $this->credential( 'zone' ) ), '.' );
		if ( '' === $zone ) {
			throw new \RuntimeException( 'RFC 2136: no zone configured.' );
		}

		$id = wp_rand( 0, 0xFFFF );

		// Header: opcode UPDATE (5), ZOCOUNT=1, UPCOUNT=1; ARCOUNT is 0 in
		// the digested message and 1 (the TSIG RR) on the wire.
		$header  = pack( 'n6', $id, 5 << 11, 1, 0, 1, 0 );
		$zone_rr = $this->encode_name( $zone ) . pack( 'n2', 6, 1 ); // SOA IN.

		// TXT RDATA: one character-string (length byte + data).
		$rdata = chr( strlen( $value ) ) . $value;

		$update_rr = $this->encode_name( $fqdn )
			. ( $add
				? pack( 'n2N', 16, 1, 60 ) . pack( 'n', strlen( $rdata ) ) . $rdata          // TXT IN TTL 60: add.
				: pack( 'n2N', 16, 254, 0 ) . pack( 'n', strlen( $rdata ) ) . $rdata );      // CLASS NONE: delete this exact RR.

		$unsigned = $header . $zone_rr . $update_rr;
		$signed   = $this->append_tsig( $unsigned, $id );

		$response = $this->exchange( $signed );

		if ( strlen( $response ) < 4 || substr( $response, 0, 2 ) !== pack( 'n', $id ) ) {
			throw new \RuntimeException( 'RFC 2136: malformed or mismatched response from the DNS server.' );
		}

		$flags = unpack( 'n', substr( $response, 2, 2 ) )[1];
		$rcode = $flags & 0x000F;
		if ( 0 !== $rcode ) {
			$names = array(
				1  => 'FORMERR',
				2  => 'SERVFAIL',
				3  => 'NXDOMAIN',
				4  => 'NOTIMP',
				5  => 'REFUSED',
				9  => 'NOTAUTH',
				10 => 'NOTZONE',
				16 => 'BADSIG',
				17 => 'BADKEY',
				18 => 'BADTIME',
			);
			throw new \RuntimeException( 'RFC 2136 update rejected: ' . ( $names[ $rcode ] ?? "RCODE {$rcode}" ) . ' (check the TSIG key and update-policy).' );
		}
	}

	/**
	 * Appends a TSIG RR (RFC 8945 §4.3): the MAC covers the unsigned message
	 * plus the TSIG "variables" (key name, class ANY, TTL 0, algorithm, time,
	 * fudge, error, other-len).
	 */
	private function append_tsig( string $unsigned, int $id ): string {
		$algorithm = strtolower( trim( $this->credential( 'algorithm' ) ) );
		if ( ! isset( self::ALGORITHMS[ $algorithm ] ) ) {
			$algorithm = 'hmac-sha256';
		}
		list( $alg_wire_name, $hash_algo ) = self::ALGORITHMS[ $algorithm ];

		$secret = base64_decode( $this->credential( 'secret' ), true );
		if ( false === $secret || '' === $secret ) {
			throw new \RuntimeException( 'RFC 2136: the TSIG secret is not valid base64.' );
		}

		$key_name = rtrim( strtolower( trim( $this->credential( 'key_name' ) ) ), '.' );
		$time     = time();
		$fudge    = 300;

		$time48 = pack( 'n', ( $time >> 32 ) & 0xFFFF ) . pack( 'N', $time & 0xFFFFFFFF );

		$variables = $this->encode_name( $key_name )
			. pack( 'nN', 255, 0 )                    // CLASS ANY, TTL 0.
			. $this->encode_name( rtrim( $alg_wire_name, '.' ) )
			. $time48
			. pack( 'n3', $fudge, 0, 0 );             // Fudge, error 0, other-len 0.

		$mac = hash_hmac( $hash_algo, $unsigned . $variables, $secret, true );

		$tsig_rdata = $this->encode_name( rtrim( $alg_wire_name, '.' ) )
			. $time48
			. pack( 'n2', $fudge, strlen( $mac ) )
			. $mac
			. pack( 'n3', $id, 0, 0 );                // Original ID, error 0, other-len 0.

		$tsig_rr = $this->encode_name( $key_name )
			. pack( 'n2N', 250, 255, 0 )              // TYPE TSIG, CLASS ANY, TTL 0.
			. pack( 'n', strlen( $tsig_rdata ) )
			. $tsig_rdata;

		// Bump ARCOUNT (bytes 10-11) from 0 to 1 for the wire message.
		return substr( $unsigned, 0, 10 ) . pack( 'n', 1 ) . substr( $unsigned, 12 ) . $tsig_rr;
	}

	private function exchange( string $message ): string {
		$server = trim( $this->credential( 'server' ) );
		$port   = 53;
		if ( str_contains( $server, ':' ) && ! str_contains( $server, ']' ) ) {
			list( $server, $port_part ) = explode( ':', $server, 2 );
			$port                       = (int) $port_part;
		}

		$errno  = 0;
		$errstr = '';
		$socket = @stream_socket_client( "tcp://{$server}:{$port}", $errno, $errstr, 15 ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- failure surfaced below with context.
		if ( false === $socket ) {
			throw new \RuntimeException( "RFC 2136: cannot reach {$server}:{$port} over TCP: {$errstr}" );
		}

		try {
			stream_set_timeout( $socket, 15 );
			fwrite( $socket, pack( 'n', strlen( $message ) ) . $message ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fwrite -- raw TCP socket, not a file.

			$length_raw = (string) fread( $socket, 2 ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fread -- raw TCP socket, not a file.
			if ( 2 !== strlen( $length_raw ) ) {
				throw new \RuntimeException( 'RFC 2136: the DNS server closed the connection without responding.' );
			}
			$length   = unpack( 'n', $length_raw )[1];
			$response = '';
			while ( strlen( $response ) < $length && ! feof( $socket ) ) {
				$chunk = (string) fread( $socket, $length - strlen( $response ) ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fread -- raw TCP socket, not a file.
				if ( '' === $chunk ) {
					break;
				}
				$response .= $chunk;
			}

			return $response;
		} finally {
			fclose( $socket ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fclose -- raw TCP socket.
		}
	}

	/**
	 * Encodes a domain name into uncompressed wire format (canonical for
	 * TSIG: lowercase).
	 */
	private function encode_name( string $name ): string {
		$wire = '';
		foreach ( explode( '.', rtrim( strtolower( $name ), '.' ) ) as $dns_label ) {
			if ( '' === $dns_label ) {
				continue;
			}
			if ( strlen( $dns_label ) > 63 ) {
				throw new \RuntimeException( 'RFC 2136: DNS label exceeds 63 octets.' );
			}
			$wire .= chr( strlen( $dns_label ) ) . $dns_label;
		}

		return $wire . "\0";
	}
}
