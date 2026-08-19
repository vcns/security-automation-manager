<?php
/**
 * Unit tests for WP_SAM\Admin\Csp_Header_Formatter.
 */

declare( strict_types=1 );

use PHPUnit\Framework\TestCase;
use WP_SAM\Admin\Csp_Header_Formatter;

class CspHeaderFormatterTest extends TestCase {

	public function test_bolds_every_directive_name_in_a_full_header(): void {
		$header = "default-src 'none'; script-src 'report-sample' 'nonce-P6QXjvPrjRk3CcrbWsNHvw'; "
			. "script-src-elem 'report-sample' 'nonce-P6QXjvPrjRk3CcrbWsNHvw'; script-src-attr 'none'; "
			. "img-src 'self'; report-uri https://example.com/wp-json/sam/v1/report";

		$html = Csp_Header_Formatter::render( $header );

		foreach ( array( 'default-src', 'script-src', 'script-src-elem', 'script-src-attr', 'img-src', 'report-uri' ) as $directive ) {
			$this->assertStringContainsString( '<strong>' . $directive . '</strong>', $html );
		}
	}

	public function test_source_lists_are_not_bolded(): void {
		$html = Csp_Header_Formatter::render( "default-src 'none'; img-src 'self'" );

		$this->assertStringNotContainsString( '<strong>&#039;none&#039;</strong>', $html );
		$this->assertStringNotContainsString( '<strong>&#039;self&#039;</strong>', $html );
		$this->assertStringContainsString( '<strong>default-src</strong> &#039;none&#039;', $html );
		$this->assertStringContainsString( '<strong>img-src</strong> &#039;self&#039;', $html );
	}

	public function test_boolean_directive_with_no_source_list_is_still_bolded(): void {
		$html = Csp_Header_Formatter::render( "default-src 'none'; upgrade-insecure-requests" );

		$this->assertStringContainsString( '<strong>upgrade-insecure-requests</strong>', $html );
	}

	public function test_clauses_stay_semicolon_separated(): void {
		$html = Csp_Header_Formatter::render( "default-src 'none'; img-src 'self'" );

		$this->assertStringContainsString( '</strong> &#039;none&#039;; <strong>img-src</strong>', $html );
	}

	public function test_empty_header_renders_empty_string(): void {
		$this->assertSame( '', Csp_Header_Formatter::render( '' ) );
	}

	public function test_output_is_escaped(): void {
		$html = Csp_Header_Formatter::render( "default-src 'none'; report-uri https://example.com/?x=<script>alert(1)</script>" );

		$this->assertStringNotContainsString( '<script>alert(1)</script>', $html );
		$this->assertStringContainsString( '&lt;script&gt;', $html );
	}
}
