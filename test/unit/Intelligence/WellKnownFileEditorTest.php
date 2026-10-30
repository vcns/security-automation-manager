<?php
/**
 * Unit tests for WP_SAM\Intelligence\Well_Known_File_Editor.
 */

declare( strict_types=1 );

use PHPUnit\Framework\TestCase;
use WP_SAM\Intelligence\Well_Known_File_Editor;
use WP_SAM\Intelligence\Well_Known_File_Store;

class WellKnownFileEditorTest extends TestCase {

	/** @var array<int, string> URLs fetched. */
	private array $fetched = array();

	/** @var array<int, string> Files whose *_Store was refreshed. */
	private array $refreshed = array();

	protected function setUp(): void {
		wp_test_reset_globals();
		$this->fetched   = array();
		$this->refreshed = array();
	}

	/** @param array|WP_Error $response What fetching the file returns. */
	private function editor( $response ): Well_Known_File_Editor {
		return new Well_Known_File_Editor(
			new Well_Known_File_Store(),
			function ( string $url ) use ( $response ) {
				$this->fetched[] = $url;
				return $response;
			},
			function ( string $key ): void {
				$this->refreshed[] = $key;
			}
		);
	}

	private function http_response( string $body, int $code = 200 ): array {
		return array(
			'response' => array( 'code' => $code ),
			'body'     => $body,
		);
	}

	public function test_a_file_with_problems_is_not_saved_fetched_or_refreshed(): void {
		$result = $this->editor( $this->http_response( '' ) )->save( 'robots', "not a rule\r\n", 1 );

		$this->assertFalse( $result['saved'] );
		$this->assertNotEmpty( $result['problems'] );
		$this->assertSame( "not a rule\n", $result['content'], 'Returned sanitised, so the editor can show it again.' );
		$this->assertNull( ( new Well_Known_File_Store() )->get( 'robots' ) );
		$this->assertSame( array(), $this->fetched );
		$this->assertSame( array(), $this->refreshed );
	}

	public function test_a_saved_file_the_site_returns_unchanged_is_recorded_as_served(): void {
		$result = $this->editor( $this->http_response( "Site: Example\r\n" ) )->save( 'humans', "Site: Example\n", 7 );

		$this->assertTrue( $result['saved'] );
		$this->assertSame( Well_Known_File_Store::CHECK_SERVED, $result['check'] );
		$this->assertSame( array( 'https://example.com/humans.txt' ), $this->fetched );
		$this->assertSame( array( 'humans' ), $this->refreshed );

		$saved = ( new Well_Known_File_Store() )->get( 'humans' );
		$this->assertSame( "Site: Example\n", $saved['content'] );
		$this->assertSame( 7, $saved['saved_by'] );
		$this->assertSame( Well_Known_File_Store::CHECK_SERVED, $saved['check'] );
	}

	/**
	 * A real file in the site's folder, a page cache, or a web server that
	 * never hands the path to WordPress all answer before this plugin can.
	 */
	public function test_a_saved_file_the_site_answers_differently_is_recorded_as_not_served(): void {
		$different = $this->editor( $this->http_response( "Site: Something else\n" ) )->save( 'humans', "Site: Example\n", 1 );
		$missing   = $this->editor( $this->http_response( 'Not found', 404 ) )->save( 'ads', "example.com, 1, DIRECT\n", 1 );

		$this->assertTrue( $different['saved'] );
		$this->assertSame( Well_Known_File_Store::CHECK_NOT_SERVED, $different['check'] );
		$this->assertSame( Well_Known_File_Store::CHECK_NOT_SERVED, $missing['check'] );
	}

	public function test_a_saved_file_the_site_cannot_be_fetched_for_is_recorded_as_unconfirmed(): void {
		$result = $this->editor( new WP_Error( 'http_request_failed', 'timed out' ) )->save( 'humans', "Site: Example\n", 1 );

		$this->assertTrue( $result['saved'] );
		$this->assertSame( Well_Known_File_Store::CHECK_UNREACHABLE, $result['check'] );
	}

	public function test_remove_stops_serving_and_refreshes_the_reading(): void {
		$editor = $this->editor( $this->http_response( "Site: Example\n" ) );
		$editor->save( 'humans', "Site: Example\n", 1 );
		$this->refreshed = array();

		$editor->remove( 'humans' );

		$this->assertNull( ( new Well_Known_File_Store() )->get( 'humans' ) );
		$this->assertFalse( get_option( Well_Known_File_Store::OPTION ) );
		$this->assertSame( array( 'humans' ), $this->refreshed );
	}

	public function test_live_content_is_what_the_site_serves_or_null(): void {
		$this->assertSame( "User-agent: *\nDisallow:\n", $this->editor( $this->http_response( "User-agent: *\r\nDisallow:\r\n" ) )->live_content( 'robots' ) );
		$this->assertNull( $this->editor( $this->http_response( 'Not found', 404 ) )->live_content( 'robots' ) );
		$this->assertNull( $this->editor( $this->http_response( '' ) )->live_content( 'robots' ) );
		$this->assertNull( $this->editor( new WP_Error( 'x', 'y' ) )->live_content( 'robots' ) );
	}
}
