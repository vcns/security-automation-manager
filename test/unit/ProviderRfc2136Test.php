<?php
/**
 * Phase 6C, RFC 2136 socket-level harness (the final Phase 6C deliverable
 * -- completes request-level coverage for all 41 registered DNS-01
 * provider drivers).
 *
 * WP_SAM\Certificates\Providers\Provider_Rfc2136 speaks the raw DNS wire
 * protocol over stream_socket_client() -- never any wp_remote_* function
 * -- so it is architecturally incompatible with
 * Dns_Provider_Contract_TestCase (the HTTP-transport framework's stubs
 * intercept wp_remote_request() et al.; there is nothing for them to
 * intercept here). PHP has no user-registerable "tcp" stream transport
 * (stream_wrapper_register() covers fopen()-style wrappers, a distinct
 * registry keyed by scheme, not the transports stream_socket_client()
 * resolves), so nothing in-process can intercept the driver's connection
 * attempt. A genuine, separate, loopback-only TCP listener is therefore
 * the only way to give this driver a real request/response cycle -- and
 * because Provider_Rfc2136::exchange() makes fully blocking
 * fwrite()/fread() calls, that listener must run in a genuinely separate
 * OS process (this test spawns test/fixtures/rfc2136-fake-server.php via
 * proc_open() for every scenario that needs one), not merely a second
 * socket in the same PHP process.
 *
 * This bespoke fixture follows the same precedent AcmednsProviderTest
 * already established for acme-dns (Batch 5): test the driver's actual
 * behaviour directly via its own hooks, rather than forcing it through a
 * contract designed around a request/response shape it doesn't have.
 *
 * Every socket in this file binds and connects on 127.0.0.1 only -- no
 * external network access occurs at any point, matching the one
 * pre-existing RFC 2136 test from Phase 6A
 * (CertificateManagerTest::test_dns_provider_transport_failure_is_recorded_as_a_failed_run,
 * a real refused connection to 127.0.0.1:1) and disclosed here in the
 * same way.
 *
 * Contrast finding, not a defect: unlike almost every HTTP-based provider
 * in this suite, RFC 2136 has no "relative name" concept at all -- every
 * resource record's owner name is sent fully qualified on the wire, which
 * is simply how the DNS protocol represents names; there is no
 * zone-relative shorthand to get wrong. Proven by
 * test_record_names_are_sent_fully_qualified_not_relative(). Similarly,
 * delete_txt_record()'s CLASS NONE deletion is an exact-match protocol
 * primitive (RFC 2136 removes only an RR whose rdata matches exactly) --
 * a well-designed, precise by-value delete at the protocol level itself,
 * proven by test_delete_sends_a_class_none_deletion_with_the_exact_value().
 *
 * Confirmed production defect (not fixed here), and dead/misleading code
 * (noted, not separately tested -- see the comment above
 * test_response_side_tsig_error_detail_is_never_inspected()):
 * send_update() only ever reads the first 4 bytes of a response (ID plus
 * flags) -- it never parses any resource record the response carries, so
 * it never inspects a response's TSIG RR at all, including that RR's own
 * Error field, which is where RFC 8945 actually represents BADSIG/BADKEY/
 * BADTIME. A rejection is still correctly detected and thrown for at the
 * header-RCODE level (commonly NOTAUTH for a TSIG failure), just without
 * the more specific reason a real server's TSIG RR would have carried.
 * Separately, and independent of any live response: `$rcode = $flags &
 * 0x000F` is mathematically bounded to [0,15], so the driver's own
 * 16 => 'BADSIG'/17 => 'BADKEY'/18 => 'BADTIME' map entries can never be
 * selected by that lookup -- dead code, confirmed by inspection alone. An
 * earlier version of this fixture incorrectly claimed a response could
 * "place RCODE 16 in the header" and have it silently masked to a false
 * NOERROR; that claim was wrong (a 4-bit field cannot hold 16 by any bit
 * manipulation) and has been removed -- see the correction comment near
 * the bottom of the RCODE section for what changed and why.
 */

declare( strict_types=1 );

use WP_SAM\Certificates\Providers\Provider_Rfc2136;

class ProviderRfc2136Test extends \PHPUnit\Framework\TestCase {

	protected function setUp(): void {
		wp_test_reset_globals();
	}

	// ── Fake-server process management ───────────────────────────────────────

	/** @return array{process:resource,pipes:array<int,resource>,port:int} */
	private function start_fake_server( string $mode, string $raw_response = '' ): array {
		$script = __DIR__ . '/../fixtures/rfc2136-fake-server.php';
		$cmd    = array( PHP_BINARY, $script, $mode, base64_encode( $raw_response ) );

		$descriptors = array(
			0 => array( 'pipe', 'r' ),
			1 => array( 'pipe', 'w' ),
			2 => array( 'pipe', 'w' ),
		);
		$process = proc_open( $cmd, $descriptors, $pipes );
		$this->assertIsResource( $process, 'failed to spawn the fake RFC 2136 server process' );

		$port_line = fgets( $pipes[1] );
		$this->assertNotFalse( $port_line, 'fake server never reported a listening port' );
		$port = (int) trim( (string) $port_line );
		$this->assertGreaterThan( 0, $port );

		return array(
			'process' => $process,
			'pipes'   => $pipes,
			'port'    => $port,
		);
	}

	/** Must only be called after the provider's blocking call has returned (successfully or by exception). */
	private function captured_request( array $server ): string {
		$line = fgets( $server['pipes'][1] );
		$this->assertNotFalse( $line, 'fake server never reported the captured request' );
		$captured = base64_decode( trim( (string) $line ), true );
		return false === $captured ? '' : $captured;
	}

	private function stop_fake_server( array $server ): void {
		foreach ( $server['pipes'] as $pipe ) {
			if ( is_resource( $pipe ) ) {
				fclose( $pipe );
			}
		}
		proc_close( $server['process'] );
	}

	// ── Fixture defaults ──────────────────────────────────────────────────────

	private function make_provider( int $port, string $algorithm = 'hmac-sha256' ): Provider_Rfc2136 {
		return new Provider_Rfc2136(
			array(
				'server'    => "127.0.0.1:{$port}",
				'zone'      => 'example.com',
				'key_name'  => 'wp-sam',
				'secret'    => base64_encode( 'fixture-tsig-shared-secret' ),
				'algorithm' => $algorithm,
			)
		);
	}

	private function fqdn(): string {
		return '_acme-challenge.www.example.com';
	}

	private function record_value(): string {
		return 'fixture-challenge-digest-value';
	}

	private const ID_SENTINEL = "\xAA\xBB";

	/** A well-formed response with the given RCODE; \xAA\xBB is replaced with the real request ID by the fake server. */
	private function rcode_response( int $rcode ): string {
		$flags = 0x8000 | ( 5 << 11 ) | $rcode; // QR=1 (response), OPCODE=UPDATE(5), RCODE in the low nibble.
		return self::ID_SENTINEL . pack( 'n5', $flags, 0, 0, 0, 0 );
	}

	private function noerror_response(): string {
		return $this->rcode_response( 0 );
	}

	// ── Wire-format parsing (mirrors what the driver itself constructs) ──────

	private function encode_name( string $name ): string {
		$wire = '';
		foreach ( explode( '.', rtrim( strtolower( $name ), '.' ) ) as $label ) {
			if ( '' === $label ) {
				continue;
			}
			$wire .= chr( strlen( $label ) ) . $label;
		}
		return $wire . "\0";
	}

	private function decode_name( string $data, int &$offset ): string {
		$labels = array();
		while ( true ) {
			$len = ord( $data[ $offset ] );
			++$offset;
			if ( 0 === $len ) {
				break;
			}
			$labels[] = substr( $data, $offset, $len );
			$offset  += $len;
		}
		return implode( '.', $labels );
	}

	/** Parses a captured request exactly as constructed by send_update()/append_tsig(). */
	private function parse_request( string $raw ): array {
		$id    = unpack( 'n', substr( $raw, 0, 2 ) )[1];
		$flags = unpack( 'n', substr( $raw, 2, 2 ) )[1];

		$offset = 12;

		$zone_name  = $this->decode_name( $raw, $offset );
		$zone_type  = unpack( 'n', substr( $raw, $offset, 2 ) )[1];
		$offset    += 2;
		$zone_class = unpack( 'n', substr( $raw, $offset, 2 ) )[1];
		$offset    += 2;

		$rr_name  = $this->decode_name( $raw, $offset );
		$rr_type  = unpack( 'n', substr( $raw, $offset, 2 ) )[1];
		$offset  += 2;
		$rr_class = unpack( 'n', substr( $raw, $offset, 2 ) )[1];
		$offset  += 2;
		$rr_ttl   = unpack( 'N', substr( $raw, $offset, 4 ) )[1];
		$offset  += 4;
		$rr_rdlen = unpack( 'n', substr( $raw, $offset, 2 ) )[1];
		$offset  += 2;
		$rr_rdata = substr( $raw, $offset, $rr_rdlen );
		$offset  += $rr_rdlen;

		$txt_len   = $rr_rdlen > 0 ? ord( $rr_rdata[0] ) : 0;
		$txt_value = substr( $rr_rdata, 1, $txt_len );

		$tsig_rr_offset = $offset;
		$tsig_name      = $this->decode_name( $raw, $offset );
		$tsig_type      = unpack( 'n', substr( $raw, $offset, 2 ) )[1];
		$offset        += 2;
		$tsig_class     = unpack( 'n', substr( $raw, $offset, 2 ) )[1];
		$offset        += 2;
		$tsig_ttl       = unpack( 'N', substr( $raw, $offset, 4 ) )[1];
		$offset        += 4;
		$tsig_rdlen     = unpack( 'n', substr( $raw, $offset, 2 ) )[1];
		$offset        += 2;

		$alg_name = $this->decode_name( $raw, $offset );
		$time_hi  = unpack( 'n', substr( $raw, $offset, 2 ) )[1];
		$offset  += 2;
		$time_lo  = unpack( 'N', substr( $raw, $offset, 4 ) )[1];
		$offset  += 4;
		$fudge    = unpack( 'n', substr( $raw, $offset, 2 ) )[1];
		$offset  += 2;
		$mac_size = unpack( 'n', substr( $raw, $offset, 2 ) )[1];
		$offset  += 2;
		$mac      = substr( $raw, $offset, $mac_size );
		$offset  += $mac_size;
		$orig_id  = unpack( 'n', substr( $raw, $offset, 2 ) )[1];

		return compact(
			'id',
			'flags',
			'zone_name',
			'zone_type',
			'zone_class',
			'rr_name',
			'rr_type',
			'rr_class',
			'rr_ttl',
			'txt_value',
			'tsig_rr_offset',
			'tsig_name',
			'tsig_ttl',
			'alg_name',
			'time_hi',
			'time_lo',
			'fudge',
			'mac',
			'orig_id'
		);
	}

	/** Recomputes the TSIG MAC exactly as append_tsig() does, and compares it to the one actually sent. */
	private function verify_tsig( string $raw, array $parsed, string $secret, string $hash_algo ): bool {
		$unsigned = substr( $raw, 0, $parsed['tsig_rr_offset'] );
		// On the wire ARCOUNT is 1 (the TSIG RR); the digested message has it at 0.
		$unsigned = substr( $unsigned, 0, 10 ) . "\x00\x00" . substr( $unsigned, 12 );

		$variables = $this->encode_name( $parsed['tsig_name'] )
			. pack( 'nN', 255, 0 )
			. $this->encode_name( $parsed['alg_name'] )
			. pack( 'n', $parsed['time_hi'] ) . pack( 'N', $parsed['time_lo'] )
			. pack( 'n3', $parsed['fudge'], 0, 0 );

		$expected_mac = hash_hmac( $hash_algo, $unsigned . $variables, $secret, true );

		return hash_equals( $expected_mac, $parsed['mac'] );
	}

	// ── Successful create/delete ──────────────────────────────────────────────

	public function test_successful_create_completes_without_throwing(): void {
		$server = $this->start_fake_server( 'respond', $this->noerror_response() );
		$provider = $this->make_provider( $server['port'] );

		$provider->create_txt_record( $this->fqdn(), $this->record_value() );

		$this->captured_request( $server );
		$this->stop_fake_server( $server );
	}

	public function test_successful_delete_completes_without_throwing(): void {
		$server = $this->start_fake_server( 'respond', $this->noerror_response() );
		$provider = $this->make_provider( $server['port'] );

		$provider->delete_txt_record( $this->fqdn(), $this->record_value() );

		$this->captured_request( $server );
		$this->stop_fake_server( $server );
	}

	// ── Message construction ──────────────────────────────────────────────────

	public function test_create_sends_an_add_txt_record_with_class_in(): void {
		$server = $this->start_fake_server( 'respond', $this->noerror_response() );
		$provider = $this->make_provider( $server['port'] );

		$provider->create_txt_record( $this->fqdn(), $this->record_value() );

		$raw    = $this->captured_request( $server );
		$this->stop_fake_server( $server );
		$parsed = $this->parse_request( $raw );

		$this->assertSame( $this->fqdn(), $parsed['rr_name'], 'the owner name is the full fqdn -- RFC 2136 has no relative-name concept' );
		$this->assertSame( 16, $parsed['rr_type'], 'TYPE TXT' );
		$this->assertSame( 1, $parsed['rr_class'], 'CLASS IN: add this RR' );
		$this->assertSame( 60, $parsed['rr_ttl'] );
		$this->assertSame( $this->record_value(), $parsed['txt_value'] );
	}

	public function test_delete_sends_a_class_none_deletion_with_the_exact_value(): void {
		$server = $this->start_fake_server( 'respond', $this->noerror_response() );
		$provider = $this->make_provider( $server['port'] );

		$provider->delete_txt_record( $this->fqdn(), $this->record_value() );

		$raw    = $this->captured_request( $server );
		$this->stop_fake_server( $server );
		$parsed = $this->parse_request( $raw );

		$this->assertSame( 16, $parsed['rr_type'], 'TYPE TXT' );
		$this->assertSame( 254, $parsed['rr_class'], 'CLASS NONE: delete only an RR matching this exact rdata' );
		$this->assertSame( 0, $parsed['rr_ttl'] );
		$this->assertSame( $this->record_value(), $parsed['txt_value'], 'deletion is by exact rdata match at the protocol level -- a well-designed, precise by-value delete' );
	}

	public function test_zone_rr_uses_the_configured_zone_name(): void {
		$server = $this->start_fake_server( 'respond', $this->noerror_response() );
		$provider = $this->make_provider( $server['port'] );

		$provider->create_txt_record( $this->fqdn(), $this->record_value() );

		$raw    = $this->captured_request( $server );
		$this->stop_fake_server( $server );
		$parsed = $this->parse_request( $raw );

		$this->assertSame( 'example.com', $parsed['zone_name'] );
		$this->assertSame( 6, $parsed['zone_type'], 'TYPE SOA' );
		$this->assertSame( 1, $parsed['zone_class'], 'CLASS IN' );
	}

	public function test_record_names_are_sent_fully_qualified_not_relative(): void {
		$server = $this->start_fake_server( 'respond', $this->noerror_response() );
		$provider = $this->make_provider( $server['port'] );

		$provider->create_txt_record( $this->fqdn(), $this->record_value() );

		$raw    = $this->captured_request( $server );
		$this->stop_fake_server( $server );
		$parsed = $this->parse_request( $raw );

		$this->assertSame(
			'_acme-challenge.www.example.com',
			$parsed['rr_name'],
			'the owner name is the full fqdn, not stripped down to a zone-relative form like "_acme-challenge.www" -- every RR owner name is fully qualified on the wire'
		);
	}

	// ── TSIG signing correctness ──────────────────────────────────────────────

	public function test_tsig_signature_is_computed_correctly_and_verifiable_by_the_server(): void {
		$server = $this->start_fake_server( 'respond', $this->noerror_response() );
		$provider = $this->make_provider( $server['port'] );

		$provider->create_txt_record( $this->fqdn(), $this->record_value() );

		$raw    = $this->captured_request( $server );
		$this->stop_fake_server( $server );
		$parsed = $this->parse_request( $raw );

		$this->assertSame( 'wp-sam', $parsed['tsig_name'] );
		$this->assertSame( 'hmac-sha256', $parsed['alg_name'] );
		$this->assertSame( 300, $parsed['fudge'] );
		$this->assertSame( $parsed['id'], $parsed['orig_id'], 'the TSIG RR carries the original message ID' );
		$this->assertTrue(
			$this->verify_tsig( $raw, $parsed, 'fixture-tsig-shared-secret', 'sha256' ),
			'recomputing HMAC-SHA256 over the digested message plus TSIG variables, using the same shared secret, must reproduce the exact MAC the driver sent'
		);
	}

	public function test_each_supported_tsig_algorithm_produces_a_verifiable_signature(): void {
		$algorithms = array(
			'hmac-sha256' => array( 'hmac-sha256', 'sha256' ),
			'hmac-sha512' => array( 'hmac-sha512', 'sha512' ),
			'hmac-sha1'   => array( 'hmac-sha1', 'sha1' ),
			'hmac-md5'    => array( 'hmac-md5.sig-alg.reg.int', 'md5' ),
		);

		foreach ( $algorithms as $configured => list( $expected_wire_name, $hash_algo ) ) {
			$server   = $this->start_fake_server( 'respond', $this->noerror_response() );
			$provider = $this->make_provider( $server['port'], $configured );

			$provider->create_txt_record( $this->fqdn(), $this->record_value() );

			$raw    = $this->captured_request( $server );
			$this->stop_fake_server( $server );
			$parsed = $this->parse_request( $raw );

			$this->assertSame( $expected_wire_name, $parsed['alg_name'], "algorithm wire name for {$configured}" );
			$this->assertTrue(
				$this->verify_tsig( $raw, $parsed, 'fixture-tsig-shared-secret', $hash_algo ),
				"the {$configured} signature must be verifiable by recomputing {$hash_algo} with the shared secret"
			);
		}
	}

	// ── Server-side rejection (RCODE handling) ────────────────────────────────

	public function test_a_provider_side_rcode_rejection_throws_with_the_rcode_name(): void {
		$cases = array(
			5  => 'REFUSED',
			9  => 'NOTAUTH',
			3  => 'NXDOMAIN',
		);

		foreach ( $cases as $rcode => $name ) {
			$server   = $this->start_fake_server( 'respond', $this->rcode_response( $rcode ) );
			$provider = $this->make_provider( $server['port'] );

			try {
				$provider->create_txt_record( $this->fqdn(), $this->record_value() );
				$this->fail( "expected an exception for RCODE {$rcode} ({$name})" );
			} catch ( \RuntimeException $e ) {
				$this->assertStringContainsString( $name, $e->getMessage() );
			} finally {
				$this->captured_request( $server );
				$this->stop_fake_server( $server );
			}
		}
	}

	// ── Response-side TSIG blindness ──────────────────────────────────────────
	//
	// Confirmed dead/misleading code (not fixed here), noted by direct
	// inspection rather than a live test: send_update() computes
	// `$rcode = $flags & 0x000F`, mathematically bounded to [0,15] by the
	// mask alone. The driver's own $names map nonetheless includes
	// 16 => 'BADSIG', 17 => 'BADKEY', 18 => 'BADTIME' -- array keys this
	// mask can never select, since no bit pattern makes `$anything & 0x000F`
	// equal 16 or higher. This is an arithmetic fact about the `&` operator,
	// not something a wire-format test is needed to demonstrate, so none is
	// asserted for it here.
	//
	// CORRECTION: an earlier version of this fixture claimed OR-ing the
	// literal integer 16 into the response flags word "placed RCODE 16 into
	// the header", silently masked to 0 and accepted as success. That was
	// wrong and has been removed. RCODE occupies bits 0-3 of the flags word;
	// bit 4 is the unrelated CD flag. `$flags |= 16` sets bit 4 only -- it
	// does not touch the RCODE bits at all, so that response was a perfectly
	// ordinary NOERROR (RCODE 0) response throughout, and the test proved
	// nothing about BADSIG. A value of 16 cannot be expressed in a 4-bit
	// field by any bit manipulation; there is no "adjacent bit" that inserts
	// it. The substantive, testable gap is different, and is what the test
	// below actually proves: the driver never parses the response beyond
	// its first 4 bytes (ID + flags), so it never reads a response's TSIG
	// resource record at all -- including the TSIG RR's own Error field,
	// which is where RFC 8945 actually represents BADSIG/BADKEY/BADTIME.

	/** A response TSIG RR whose Error field carries a specific RFC 8945 error code. */
	private function response_tsig_rr( int $error ): string {
		$key_name = 'wp-sam';
		$mac      = '';

		$tsig_rdata = $this->encode_name( 'hmac-sha256' )
			. pack( 'n', 0 ) . pack( 'N', 0 ) // time48, kept at zero for this fixture.
			. pack( 'n2', 300, strlen( $mac ) )
			. $mac
			. self::ID_SENTINEL // original ID -- echoed by the fake server, same as the message ID.
			. pack( 'n2', $error, 0 );

		return $this->encode_name( $key_name )
			. pack( 'n2N', 250, 255, 0 )
			. pack( 'n', strlen( $tsig_rdata ) )
			. $tsig_rdata;
	}

	/** A NOTAUTH response that also carries a genuine TSIG RR with a specific Error field. */
	private function notauth_response_with_tsig_error( int $error ): string {
		$header = self::ID_SENTINEL . pack( 'n5', 0x8000 | ( 5 << 11 ) | 9, 0, 0, 0, 1 );
		return $header . $this->response_tsig_rr( $error );
	}

	/**
	 * The real, wire-format-verified finding behind the removed BADSIG
	 * claim above: send_update() reads only the first 4 bytes of the
	 * response (ID + flags) and never parses any resource record in it --
	 * so even when the fake server sends back a genuine TSIG RR whose
	 * Error field is set to BADSIG(16), the driver's exception carries only
	 * the generic header RCODE name (NOTAUTH) a real server would set at
	 * the header level, never the more specific TSIG Error detail actually
	 * present in the wire response.
	 * [Unverified]: how commonly real servers populate the TSIG Error
	 * field on a rejection versus relying on the header RCODE alone -- the
	 * code-level blindness (this driver never reads that field under any
	 * circumstance) is confirmed regardless.
	 */
	public function test_response_side_tsig_error_detail_is_never_inspected(): void {
		$server   = $this->start_fake_server( 'respond', $this->notauth_response_with_tsig_error( 16 ) );
		$provider = $this->make_provider( $server['port'] );

		try {
			$provider->create_txt_record( $this->fqdn(), $this->record_value() );
			$this->fail( 'expected an exception for a NOTAUTH response' );
		} catch ( \RuntimeException $e ) {
			$this->assertStringContainsString( 'NOTAUTH', $e->getMessage(), 'the header RCODE is still correctly detected and thrown for' );
			$this->assertStringNotContainsString( 'BADSIG', $e->getMessage(), 'the response TSIG RR\'s own Error field (set to BADSIG here) is never read at all' );
		} finally {
			$this->captured_request( $server );
			$this->stop_fake_server( $server );
		}
	}

	// ── Malformed / mismatched responses ──────────────────────────────────────

	public function test_a_mismatched_response_id_is_treated_as_malformed(): void {
		// Fixed, deliberately-wrong ID (0x0000) -- not the sentinel, so it is
		// never replaced with the real request ID and will not match it.
		$server   = $this->start_fake_server( 'respond', pack( 'n6', 0, 0, 0, 0, 0, 0 ) );
		$provider = $this->make_provider( $server['port'] );

		try {
			$provider->create_txt_record( $this->fqdn(), $this->record_value() );
			$this->fail( 'expected an exception when the response ID does not match the request' );
		} catch ( \RuntimeException $e ) {
			$this->assertStringContainsString( 'malformed or mismatched response', $e->getMessage() );
		} finally {
			$this->captured_request( $server );
			$this->stop_fake_server( $server );
		}
	}

	public function test_a_response_shorter_than_a_header_is_treated_as_malformed(): void {
		$server   = $this->start_fake_server( 'respond', "\x00\x01" ); // 2 bytes -- below the 4-byte minimum.
		$provider = $this->make_provider( $server['port'] );

		try {
			$provider->create_txt_record( $this->fqdn(), $this->record_value() );
			$this->fail( 'expected an exception for a response shorter than 4 bytes' );
		} catch ( \RuntimeException $e ) {
			$this->assertStringContainsString( 'malformed or mismatched response', $e->getMessage() );
		} finally {
			$this->captured_request( $server );
			$this->stop_fake_server( $server );
		}
	}

	public function test_the_server_closing_without_responding_throws(): void {
		$server   = $this->start_fake_server( 'close' );
		$provider = $this->make_provider( $server['port'] );

		try {
			$provider->create_txt_record( $this->fqdn(), $this->record_value() );
			$this->fail( 'expected an exception when the server closes without responding' );
		} catch ( \RuntimeException $e ) {
			$this->assertStringContainsString( 'closed the connection without responding', $e->getMessage() );
		} finally {
			$this->captured_request( $server );
			$this->stop_fake_server( $server );
		}
	}

	// ── Transport failure (genuine, no fake server involved) ──────────────────

	public function test_a_genuinely_refused_connection_propagates_a_clear_transport_error(): void {
		// 127.0.0.1:1 is a reserved/unassigned port -- the connection is
		// refused immediately at the OS level, no real DNS traffic occurs.
		// Matches the same, already-established Phase 6A precedent.
		$provider = $this->make_provider( 1 );

		try {
			$provider->create_txt_record( $this->fqdn(), $this->record_value() );
			$this->fail( 'expected an exception when the TCP connection is refused' );
		} catch ( \RuntimeException $e ) {
			$this->assertStringContainsString( 'cannot reach', $e->getMessage() );
			$this->assertStringContainsString( 'over TCP', $e->getMessage() );
		}
	}

	// ── Pure-validation failures (no connection attempted at all) ─────────────

	public function test_no_zone_configured_throws_before_any_connection_is_attempted(): void {
		$provider = new Provider_Rfc2136(
			array(
				'server'    => '127.0.0.1:1', // would be refused anyway -- proves this is never even reached.
				'zone'      => '',
				'key_name'  => 'wp-sam',
				'secret'    => base64_encode( 'x' ),
				'algorithm' => 'hmac-sha256',
			)
		);

		$this->expectException( \RuntimeException::class );
		$this->expectExceptionMessage( 'RFC 2136: no zone configured.' );

		$provider->create_txt_record( $this->fqdn(), $this->record_value() );
	}

	public function test_an_invalid_base64_tsig_secret_throws_before_any_connection_is_attempted(): void {
		$provider = new Provider_Rfc2136(
			array(
				'server'    => '127.0.0.1:1',
				'zone'      => 'example.com',
				'key_name'  => 'wp-sam',
				'secret'    => 'not valid base64!!! ***',
				'algorithm' => 'hmac-sha256',
			)
		);

		$this->expectException( \RuntimeException::class );
		$this->expectExceptionMessage( 'RFC 2136: the TSIG secret is not valid base64.' );

		$provider->create_txt_record( $this->fqdn(), $this->record_value() );
	}

	public function test_a_dns_label_exceeding_63_octets_throws_before_any_connection_is_attempted(): void {
		$provider     = new Provider_Rfc2136(
			array(
				'server'    => '127.0.0.1:1',
				'zone'      => 'example.com',
				'key_name'  => 'wp-sam',
				'secret'    => base64_encode( 'x' ),
				'algorithm' => 'hmac-sha256',
			)
		);
		$oversized_fqdn = str_repeat( 'a', 64 ) . '.example.com';

		$this->expectException( \RuntimeException::class );
		$this->expectExceptionMessage( 'RFC 2136: DNS label exceeds 63 octets.' );

		$provider->create_txt_record( $oversized_fqdn, $this->record_value() );
	}
}
