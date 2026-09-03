<?php
/**
 * Unit tests for WP_SAM\Admin\Pillar_Registry.
 */

declare( strict_types=1 );

use PHPUnit\Framework\TestCase;
use WP_SAM\Admin\Pillar_Registry;
use WP_SAM\Admin\Status_Badge;
use WP_SAM\Security\Cross_Origin_Embedder_Policy_Builder;
use WP_SAM\Security\Cross_Origin_Opener_Policy_Builder;
use WP_SAM\Security\Dependency_Governance_Builder;
use WP_SAM\Security\X_Frame_Options_Builder;

class PillarRegistryTest extends TestCase {

	protected function setUp(): void {
		wp_test_reset_globals();
	}

	private function row( bool $enabled, array $payload = array() ): array {
		return array(
			'enabled' => $enabled,
			'payload' => wp_json_encode( $payload ),
		);
	}

	public function test_pillars_returns_thirteen_entries_sorted_by_label(): void {
		$pillars = Pillar_Registry::pillars();
		$labels  = array_values( array_map( static fn( array $p ): string => $p['label'], $pillars ) );
		$sorted  = $labels;
		usort( $sorted, static fn( string $a, string $b ): int => strcasecmp( $a, $b ) );

		$this->assertCount( 14, $pillars );
		$this->assertSame( $sorted, $labels );
	}

	public function test_resolve_status_with_no_row_is_not_configured(): void {
		$status = Pillar_Registry::resolve_status( X_Frame_Options_Builder::PILLAR_KEY, null );

		$this->assertSame( Status_Badge::STATE_NOT_CONFIGURED, $status['state'] );
	}

	public function test_resolve_status_disabled_wins_over_a_stored_mode(): void {
		$row = $this->row( false, array( 'mode' => 'enforce' ) );

		$status = Pillar_Registry::resolve_status( Cross_Origin_Opener_Policy_Builder::PILLAR_KEY, $row );

		$this->assertSame( Status_Badge::STATE_DISABLED, $status['state'] );
	}

	public function test_resolve_status_enabled_only_pillar_is_active_once_enabled(): void {
		$status = Pillar_Registry::resolve_status( X_Frame_Options_Builder::PILLAR_KEY, $this->row( true ) );

		$this->assertSame( Status_Badge::STATE_ACTIVE, $status['state'] );
	}

	/**
	 * @dataProvider coop_coep_mode_provider
	 */
	public function test_resolve_status_maps_coop_coep_modes( string $pillar_key, string $raw_mode, string $expected_state ): void {
		$status = Pillar_Registry::resolve_status( $pillar_key, $this->row( true, array( 'mode' => $raw_mode ) ) );

		$this->assertSame( $expected_state, $status['state'] );
	}

	public static function coop_coep_mode_provider(): array {
		return array(
			'coop disabled'    => array( Cross_Origin_Opener_Policy_Builder::PILLAR_KEY, 'disabled', Status_Badge::STATE_DISABLED ),
			'coop report-only' => array( Cross_Origin_Opener_Policy_Builder::PILLAR_KEY, 'report-only', Status_Badge::STATE_REPORT_ONLY ),
			'coop enforce'     => array( Cross_Origin_Opener_Policy_Builder::PILLAR_KEY, 'enforce', Status_Badge::STATE_ACTIVE ),
			'coep disabled'    => array( Cross_Origin_Embedder_Policy_Builder::PILLAR_KEY, 'disabled', Status_Badge::STATE_DISABLED ),
			'coep report-only' => array( Cross_Origin_Embedder_Policy_Builder::PILLAR_KEY, 'report-only', Status_Badge::STATE_REPORT_ONLY ),
			'coep enforce'     => array( Cross_Origin_Embedder_Policy_Builder::PILLAR_KEY, 'enforce', Status_Badge::STATE_ACTIVE ),
		);
	}

	public function test_resolve_status_maps_dependency_governance_modes(): void {
		$report  = Pillar_Registry::resolve_status( Dependency_Governance_Builder::PILLAR_KEY, $this->row( true, array( 'mode' => 'report' ) ) );
		$enforce = Pillar_Registry::resolve_status( Dependency_Governance_Builder::PILLAR_KEY, $this->row( true, array( 'mode' => 'enforce' ) ) );

		$this->assertSame( Status_Badge::STATE_REPORT_ONLY, $report['state'] );
		$this->assertSame( Status_Badge::STATE_ACTIVE, $enforce['state'] );
	}

	public function test_fetch_rows_buckets_by_pillar_then_surface(): void {
		$GLOBALS['_wpdb_get_results'] = array(
			array(
				'pillar'  => X_Frame_Options_Builder::PILLAR_KEY,
				'surface' => 'frontend',
				'enabled' => '1',
				'payload' => '{}',
			),
			array(
				'pillar'  => X_Frame_Options_Builder::PILLAR_KEY,
				'surface' => 'admin',
				'enabled' => '0',
				'payload' => '{}',
			),
		);

		$rows = Pillar_Registry::fetch_rows();

		$this->assertTrue( $rows[ X_Frame_Options_Builder::PILLAR_KEY ]['frontend']['enabled'] );
		$this->assertFalse( $rows[ X_Frame_Options_Builder::PILLAR_KEY ]['admin']['enabled'] );
	}
}
