<?php
/**
 * SAM security scorecard (Customer-Centred Administration Experience spec
 * §8): factual state counts -- Protected / Learning / Needs attention --
 * not a synthetic score.
 *
 * Bucketing rule (spec §8.2 explicitly describes the Learning tile as
 * covering "collecting evidence, monitoring... or non-enforcing" -- one
 * tile, not two): Protection_Status::STATE_PROTECTED counts as protected;
 * STATE_LEARNING and STATE_MONITORING both count as learning;
 * STATE_NOT_IN_USE and STATE_UNAVAILABLE count toward neither -- a
 * capability intentionally or environmentally not in use is never
 * presented as a failure (spec §10.2), and symmetrically must never
 * inflate "protected" either.
 *
 * needs_attention is Action_Centre::count_open(), not a second independent
 * count of Protection_Status rows in that state -- an area needing
 * attention is expected to already have a corresponding Action Centre
 * item, so counting both would double-count the same underlying issue.
 */

declare( strict_types=1 );

namespace WP_SAM\Admin;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class Security_Scorecard {

	/** @return array{protected:int, learning:int, needs_attention:int} */
	public function counts(): array {
		$protected = 0;
		$learning  = 0;

		foreach ( ( new Protection_Status() )->areas() as $area ) {
			if ( Protection_Status::STATE_PROTECTED === $area['state'] ) {
				++$protected;
			} elseif ( in_array( $area['state'], array( Protection_Status::STATE_LEARNING, Protection_Status::STATE_MONITORING ), true ) ) {
				++$learning;
			}
		}

		return array(
			'protected'       => $protected,
			'learning'        => $learning,
			'needs_attention' => ( new Action_Centre() )->count_open(),
		);
	}
}
