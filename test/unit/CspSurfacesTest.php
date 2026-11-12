<?php
/**
 * Unit tests for WP_SAM\CSP\Csp_Surfaces -- the single list of surfaces CSP
 * manages. The REST API ('api') is deliberately not one of them (see the
 * class docblock); other pillars still treat it as a surface.
 */

declare( strict_types=1 );

use PHPUnit\Framework\TestCase;
use WP_SAM\CSP\Automation_Config;
use WP_SAM\CSP\Csp_Surfaces;

class CspSurfacesTest extends TestCase {

	public function test_all_is_exactly_frontend_admin_and_login(): void {
		$this->assertSame( array( 'frontend', 'admin', 'login' ), Csp_Surfaces::ALL );
		$this->assertNotContains( 'api', Csp_Surfaces::ALL );
	}

	public function test_automation_config_surfaces_is_the_same_list(): void {
		$this->assertSame( Csp_Surfaces::ALL, Automation_Config::SURFACES );
	}

	public function test_sql_list_quotes_every_surface_for_a_literal_in_clause(): void {
		$this->assertSame( "'frontend', 'admin', 'login'", Csp_Surfaces::sql_list() );
	}
}
