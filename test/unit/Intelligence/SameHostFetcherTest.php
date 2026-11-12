<?php
/**
 * Unit tests for WP_SAM\Intelligence\Same_Host_Fetcher -- a self-fetch must
 * follow a redirect only while it stays on the requested host, so a
 * staging site redirecting unrecognised IPs to production never reports
 * production's files as its own.
 */

declare( strict_types=1 );

use PHPUnit\Framework\TestCase;
use WP_SAM\Intelligence\Same_Host_Fetcher;

class SameHostFetcherTest extends TestCase {

	/** @var array<int, array{url:string, args:array}> */
	private array $calls = array();

	protected function setUp(): void {
		wp_test_reset_globals();
		$this->calls = array();
	}

	private function response( int $code, string $location = '', string $body = '' ): array {
		return array(
			'response' => array( 'code' => $code ),
			'headers'  => '' !== $location ? array( 'location' => $location ) : array(),
			'body'     => $body,
		);
	}

	/** @param array<int, array|WP_Error> $responses Returned in order, one per request. */
	private function fetcher( array $responses ): Same_Host_Fetcher {
		return new Same_Host_Fetcher(
			function ( string $url, array $args ) use ( &$responses ) {
				$this->calls[] = array(
					'url'  => $url,
					'args' => $args,
				);
				return array_shift( $responses );
			}
		);
	}

	public function test_a_non_redirect_response_is_returned_as_is_with_redirection_disabled(): void {
		$result = $this->fetcher( array( $this->response( 200, '', 'hello' ) ) )->get( 'https://example.com/robots.txt', array( 'timeout' => 10 ) );

		$this->assertSame( 'hello', wp_remote_retrieve_body( $result ) );
		$this->assertCount( 1, $this->calls );
		$this->assertSame( 0, $this->calls[0]['args']['redirection'] );
		$this->assertSame( 10, $this->calls[0]['args']['timeout'] );
	}

	public function test_a_same_host_redirect_is_followed(): void {
		$result = $this->fetcher(
			array(
				$this->response( 301, 'https://example.com/new-robots.txt' ),
				$this->response( 200, '', 'final' ),
			)
		)->get( 'https://example.com/robots.txt' );

		$this->assertSame( 'final', wp_remote_retrieve_body( $result ) );
		$this->assertSame( 'https://example.com/new-robots.txt', $this->calls[1]['url'] );
	}

	public function test_a_relative_location_is_resolved_against_the_current_url(): void {
		$this->fetcher(
			array(
				$this->response( 302, '/moved/robots.txt' ),
				$this->response( 302, 'final.txt' ),
				$this->response( 200 ),
			)
		)->get( 'https://example.com/robots.txt' );

		$this->assertSame( 'https://example.com/moved/robots.txt', $this->calls[1]['url'] );
		$this->assertSame( 'https://example.com/moved/final.txt', $this->calls[2]['url'] );
	}

	public function test_a_www_variant_and_an_https_upgrade_count_as_the_same_host(): void {
		$result = $this->fetcher(
			array(
				$this->response( 301, 'https://WWW.Example.com/robots.txt' ),
				$this->response( 200, '', 'www copy' ),
			)
		)->get( 'http://example.com/robots.txt' );

		$this->assertSame( 'www copy', wp_remote_retrieve_body( $result ) );
		$this->assertCount( 2, $this->calls );
	}

	public function test_a_redirect_to_another_host_is_not_followed_or_recorded(): void {
		$result = $this->fetcher(
			array(
				$this->response( 301, 'https://other-copy.example.org/robots.txt' ),
				$this->response( 200, '', 'other copy' ),
			)
		)->get( 'https://example.com/robots.txt' );

		$this->assertInstanceOf( WP_Error::class, $result );
		$this->assertSame( 'wp_sam_offsite_redirect', $result->get_error_code() );
		$this->assertSame( "Redirected away from this site (HTTP 301), so this site's own copy could not be read.", $result->get_error_message() );
		// SAM knows only its own address: the error never says where the
		// redirect pointed, which is often another copy of this site.
		$this->assertSame( array( 'code' => 301 ), $result->get_error_data() );
		$this->assertCount( 1, $this->calls, 'The off-site Location must never be requested.' );
	}

	public function test_a_redirect_loop_stops_with_an_error(): void {
		$loop = array_fill( 0, 10, $this->response( 302, 'https://example.com/robots.txt' ) );

		$result = $this->fetcher( $loop )->get( 'https://example.com/robots.txt' );

		$this->assertInstanceOf( WP_Error::class, $result );
		$this->assertSame( 'wp_sam_too_many_redirects', $result->get_error_code() );
		$this->assertCount( 6, $this->calls, 'The original request plus at most five followed redirects.' );
	}

	public function test_a_transport_error_is_passed_through(): void {
		$result = $this->fetcher( array( new WP_Error( 'http_request_failed', 'timeout' ) ) )->get( 'https://example.com/robots.txt' );

		$this->assertSame( 'http_request_failed', $result->get_error_code() );
	}

	public function test_the_default_transport_is_wp_remote_get_with_redirection_disabled(): void {
		$GLOBALS['_wp_remote_get_response'] = $this->response( 200 );

		( new Same_Host_Fetcher() )->get( 'https://example.com/robots.txt' );

		$this->assertSame( 0, $GLOBALS['_wp_remote_get_requests'][0]['args']['redirection'] );
	}
}
