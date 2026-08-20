<?php
/**
 * Unit tests for WP_SAM\Certificates\Challenge_Http.
 *
 * resolve() is the pure decision logic maybe_serve_token() acts on, tested
 * exhaustively on its own below. maybe_serve_token() itself calls
 * status_header()/header()/echo/exit() on every matched request -- exit()
 * can't be observed from a normal PHPUnit process, so the wrapper-level
 * tests use Challenge_Http_Test_Double (defined at the bottom of this file),
 * which overrides the four small emit_*()/terminate() methods the real
 * class's maybe_serve_token() calls to capture what was decided instead of
 * actually sending headers or exiting. Production's own emit_*()/terminate()
 * implementations are untouched and still call the real WordPress/PHP
 * functions -- only the injected in the test double.
 */

declare( strict_types=1 );

use PHPUnit\Framework\TestCase;
use WP_SAM\Certificates\Challenge_Http;

class ChallengeHttpTest extends TestCase {

	private Challenge_Http $challenge;

	protected function setUp(): void {
		wp_test_reset_globals();
		$this->challenge = new Challenge_Http();
	}

	// ── Token storage ─────────────────────────────────────────────────────────

	public function test_put_token_then_delete_token_round_trips_via_options(): void {
		$this->challenge->put_token( 'tok123', 'tok123.thumbprint' );

		$stored = $GLOBALS['_wp_options']['wp_sam_acme_http_tokens'];
		$this->assertSame( 'tok123.thumbprint', $stored['tok123']['key_authorization'] );
		$this->assertIsInt( $stored['tok123']['created_at'] );

		$this->challenge->delete_token( 'tok123' );
		$this->assertArrayNotHasKey( 'tok123', $GLOBALS['_wp_options']['wp_sam_acme_http_tokens'] );
	}

	public function test_multiple_tokens_coexist(): void {
		$this->challenge->put_token( 'tok-a', 'a.thumb' );
		$this->challenge->put_token( 'tok-b', 'b.thumb' );

		$this->challenge->delete_token( 'tok-a' );

		$stored = $GLOBALS['_wp_options']['wp_sam_acme_http_tokens'];
		$this->assertArrayNotHasKey( 'tok-a', $stored );
		$this->assertSame( 'b.thumb', $stored['tok-b']['key_authorization'] );
	}

	// ── Valid challenge serving ───────────────────────────────────────────────

	public function test_resolve_serves_a_valid_known_token(): void {
		$this->challenge->put_token( 'valid-token', 'valid-token.thumbprint123' );

		$result = $this->challenge->resolve( '/.well-known/acme-challenge/valid-token' );

		$this->assertSame( array( 'status' => 200, 'body' => 'valid-token.thumbprint123' ), $result );
	}

	// ── Unknown token ─────────────────────────────────────────────────────────

	public function test_resolve_returns_404_for_an_unknown_token(): void {
		$this->challenge->put_token( 'known-token', 'known.thumb' );

		$result = $this->challenge->resolve( '/.well-known/acme-challenge/never-issued' );

		$this->assertSame( array( 'status' => 404, 'body' => null ), $result );
	}

	public function test_resolve_returns_404_for_an_empty_token(): void {
		$result = $this->challenge->resolve( '/.well-known/acme-challenge/' );

		$this->assertSame( array( 'status' => 404, 'body' => null ), $result );
	}

	// ── Expired or removed token ──────────────────────────────────────────────

	public function test_resolve_returns_404_for_a_token_older_than_one_day(): void {
		$GLOBALS['_wp_options']['wp_sam_acme_http_tokens'] = array(
			'stale-token' => array(
				'key_authorization' => 'stale.thumb',
				'created_at'        => time() - DAY_IN_SECONDS - 1,
			),
		);

		$result = $this->challenge->resolve( '/.well-known/acme-challenge/stale-token' );

		$this->assertSame( array( 'status' => 404, 'body' => null ), $result );
	}

	public function test_resolve_serves_a_token_just_under_one_day_old(): void {
		$GLOBALS['_wp_options']['wp_sam_acme_http_tokens'] = array(
			'fresh-token' => array(
				'key_authorization' => 'fresh.thumb',
				'created_at'        => time() - DAY_IN_SECONDS + 60,
			),
		);

		$result = $this->challenge->resolve( '/.well-known/acme-challenge/fresh-token' );

		$this->assertSame( array( 'status' => 200, 'body' => 'fresh.thumb' ), $result );
	}

	public function test_resolve_returns_404_after_the_token_is_deleted(): void {
		$this->challenge->put_token( 'consumed-token', 'consumed.thumb' );
		$this->challenge->delete_token( 'consumed-token' );

		$result = $this->challenge->resolve( '/.well-known/acme-challenge/consumed-token' );

		$this->assertSame( array( 'status' => 404, 'body' => null ), $result );
	}

	// ── Invalid path ──────────────────────────────────────────────────────────

	public function test_resolve_returns_null_for_a_path_outside_the_challenge_prefix(): void {
		$this->challenge->put_token( 'valid-token', 'valid.thumb' );

		$this->assertNull( $this->challenge->resolve( '/wp-admin/admin.php' ) );
		$this->assertNull( $this->challenge->resolve( '/' ) );
		$this->assertNull( $this->challenge->resolve( '' ) );
		$this->assertNull( $this->challenge->resolve( '/.well-known/other-thing/valid-token' ) );
	}

	// ── Traversal attempts ────────────────────────────────────────────────────

	public function test_resolve_treats_a_traversal_shaped_token_as_an_ordinary_unknown_token(): void {
		// Token lookup is a plain associative-array key match, never a
		// filesystem read -- a "../../wp-config.php"-shaped token has no
		// special meaning and is rejected exactly like any other unknown
		// token, not treated as a path to resolve on disk.
		$this->challenge->put_token( 'legit-token', 'legit.thumb' );

		$result = $this->challenge->resolve( '/.well-known/acme-challenge/../../../etc/passwd' );

		$this->assertSame( array( 'status' => 404, 'body' => null ), $result );
	}

	public function test_resolve_does_not_leak_an_unrelated_stored_token_via_traversal(): void {
		$this->challenge->put_token( '..', 'should-never-be-served-via-traversal' );

		// A traversal-shaped request that would, if this were filesystem-backed,
		// "resolve" to the parent directory -- here it's just the literal
		// string "..", which happens to collide with a token an attacker can't
		// have caused to be stored (put_token() is only ever called with a
		// server-generated ACME token). Confirms the lookup has no path
		// semantics either way.
		$result = $this->challenge->resolve( '/.well-known/acme-challenge/..' );

		$this->assertSame( array( 'status' => 200, 'body' => 'should-never-be-served-via-traversal' ), $result );
	}

	// ── maybe_serve_token() wrapper: unmatched path, via the real class ───────

	public function test_maybe_serve_token_is_a_no_op_for_an_unrelated_path(): void {
		$_SERVER['REQUEST_URI'] = '/wp-login.php';

		// The real class, not the test double -- there's nothing to capture
		// here since the unmatched-path branch never reaches emit_*()/
		// terminate() at all; reaching this line is the proof.
		( new Challenge_Http() )->maybe_serve_token();

		$this->assertSame( array(), $GLOBALS['_wp_status_header_calls'] );
	}

	// ── maybe_serve_token() wrapper: matched paths, via the test double ──────

	public function test_wrapper_emits_200_the_body_and_terminates_for_a_matched_token(): void {
		$double = new Challenge_Http_Test_Double();
		$double->put_token( 'matched-token', 'matched-token.thumbprint-value' );
		$_SERVER['REQUEST_URI'] = '/.well-known/acme-challenge/matched-token';

		$double->maybe_serve_token();

		$this->assertSame( array( 200 ), $double->emitted_statuses );
		$this->assertSame( array( 'text/plain' ), $double->emitted_content_types );
		$this->assertSame( array( 'matched-token.thumbprint-value' ), $double->emitted_bodies );
		$this->assertTrue( $double->terminated, 'a matched request must request termination' );
	}

	public function test_wrapper_emits_404_and_terminates_with_no_body_for_an_unknown_token(): void {
		$double = new Challenge_Http_Test_Double();
		$double->put_token( 'a-real-token', 'a-real-token.thumb' );
		$_SERVER['REQUEST_URI'] = '/.well-known/acme-challenge/completely-different-token';

		$double->maybe_serve_token();

		$this->assertSame( array( 404 ), $double->emitted_statuses );
		$this->assertSame( array(), $double->emitted_content_types, 'a 404 must not emit a Content-Type' );
		$this->assertSame( array(), $double->emitted_bodies, 'a 404 must not emit a body' );
		$this->assertTrue( $double->terminated );
	}

	public function test_wrapper_does_not_terminate_for_an_unrelated_path(): void {
		$double = new Challenge_Http_Test_Double();
		$_SERVER['REQUEST_URI'] = '/wp-login.php';

		$double->maybe_serve_token();

		$this->assertSame( array(), $double->emitted_statuses );
		$this->assertFalse( $double->terminated, 'a request outside the challenge prefix must fall through to normal WordPress routing, not terminate' );
	}

	public function test_wrapper_404_does_not_disclose_the_stored_token_of_an_unrelated_valid_token(): void {
		// A request for one unknown token must not leak *any* other token's
		// key authorization -- resolve() already guarantees this (it looks up
		// exactly the requested token), but this proves the wrapper doesn't
		// somehow emit something else's body on a 404 either.
		$double = new Challenge_Http_Test_Double();
		$double->put_token( 'someone-elses-real-token', 'someone-elses-real-token.thumb-secret' );
		$_SERVER['REQUEST_URI'] = '/.well-known/acme-challenge/not-that-token';

		$double->maybe_serve_token();

		$this->assertSame( array(), $double->emitted_bodies );
		foreach ( $double->emitted_statuses as $status ) {
			$this->assertNotSame( 200, $status );
		}
	}
}

/**
 * Challenge_Http subclass for wrapper-level tests. Captures what
 * maybe_serve_token() decided to emit instead of sending real headers or
 * exiting -- production's own emit_*()/terminate() (called by the real
 * class) are untouched; only this test-only subclass overrides them.
 */
final class Challenge_Http_Test_Double extends Challenge_Http {

	public array $emitted_statuses = array();
	public array $emitted_content_types = array();
	public array $emitted_bodies = array();
	public bool $terminated = false;

	protected function emit_status( int $status ): void {
		$this->emitted_statuses[] = $status;
	}

	protected function emit_content_type( string $content_type ): void {
		$this->emitted_content_types[] = $content_type;
	}

	protected function emit_body( string $body ): void {
		$this->emitted_bodies[] = $body;
	}

	protected function terminate(): void {
		$this->terminated = true;
		// Deliberately no exit() -- this is exactly what makes the wrapper
		// testable: control returns to the caller so assertions can run.
	}
}
