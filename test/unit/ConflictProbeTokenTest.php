<?php
/**
 * Unit tests for WP_SAM\Security\Conflict_Probe_Token.
 */

declare( strict_types=1 );

use PHPUnit\Framework\TestCase;
use WP_SAM\Security\Conflict_Probe_Token;

class ConflictProbeTokenTest extends TestCase {

	protected function setUp(): void {
		wp_test_reset_globals();
	}

	public function test_an_issued_token_is_valid_until_revoked(): void {
		$token = Conflict_Probe_Token::issue();

		$this->assertMatchesRegularExpression( '/^[0-9a-f]{64}$/', $token );
		$this->assertTrue( Conflict_Probe_Token::is_valid( $token ) );

		Conflict_Probe_Token::revoke( $token );

		$this->assertFalse( Conflict_Probe_Token::is_valid( $token ) );
	}

	public function test_the_token_itself_is_never_stored(): void {
		$token = Conflict_Probe_Token::issue();

		$this->assertStringNotContainsString( $token, (string) wp_json_encode( $GLOBALS['_wp_transients'] ) );
	}

	public function test_the_old_fixed_value_and_other_junk_are_rejected_without_a_lookup(): void {
		foreach ( array( '1', '', 'true', str_repeat( 'g', 64 ), str_repeat( 'a', 63 ) ) as $value ) {
			$this->assertFalse( Conflict_Probe_Token::is_valid( $value ), $value );
		}
		$this->assertSame( array(), $GLOBALS['_wp_transients'] );
	}

	public function test_a_well_formed_but_unissued_token_is_rejected(): void {
		Conflict_Probe_Token::issue();

		$this->assertFalse( Conflict_Probe_Token::is_valid( str_repeat( 'a', 64 ) ) );
	}
}
