<?php
/**
 * Shared base for deterministic, regex-rule-based detectors.
 *
 * A concrete subclass supplies only rules() (a list of named patterns with
 * a severity/confidence/description each) and subject() (what string to
 * match those patterns against, built from the request context). Matching,
 * decoding, and severity-ranking all live here, once, so a new detector
 * family is a declarative rule list, not another hand-rolled request-flow
 * integration -- the exact thing Phase 3B's Detector/Detector_Registry/
 * Detector_Engine skeleton exists to make possible.
 *
 * evaluate() reports the HIGHEST-severity matching rule, not the first one
 * in declaration order: a broad rule (e.g. ".git/ anywhere") and a narrower,
 * more specific rule (e.g. ".git/config" exactly) can both match the same
 * request, and the more specific/severe one should win regardless of where
 * either happens to sit in the rules() list.
 */

declare( strict_types=1 );

namespace WP_SAM\Intelligence\Detectors;

use WP_SAM\Intelligence\Detector;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

abstract class Pattern_Detector extends Detector {

	protected const DEFAULT_CONFIDENCE = 0.75;

	private const MAX_SUBJECT_LENGTH = 4096;

	private const SEVERITY_ORDER = array(
		'low'      => 1,
		'medium'   => 2,
		'high'     => 3,
		'critical' => 4,
		'unknown'  => 5,
	);

	/**
	 * @return array<int, array{id:string, pattern:string, severity:string, description:string, confidence?:float}>
	 */
	abstract protected function rules(): array;

	/** @param array<string, mixed> $context Request context built by Request_Observer. */
	abstract protected function subject( array $context ): string;

	/**
	 * Bumped whenever rules() changes -- carried into every Finding's detail
	 * so an evidence row is traceable to the exact ruleset version that
	 * produced it.
	 */
	protected function ruleset_version(): string {
		return '1';
	}

	final public function evaluate( array $context ): ?array {
		$subject = substr( self::decode( $this->subject( $context ) ), 0, self::MAX_SUBJECT_LENGTH );
		if ( '' === $subject ) {
			return null;
		}

		$best  = null;
		$count = 0;

		foreach ( $this->rules() as $rule ) {
			if ( 1 !== preg_match( $rule['pattern'], $subject ) ) {
				continue;
			}
			++$count;
			if ( null === $best || self::outranks( $rule['severity'], $best['severity'] ) ) {
				$best = $rule;
			}
		}

		if ( null === $best ) {
			return null;
		}

		return array(
			'severity'   => $best['severity'],
			'confidence' => $best['confidence'] ?? static::DEFAULT_CONFIDENCE,
			'detail'     => array(
				'rule_id'            => $best['id'],
				'description'        => $best['description'],
				'ruleset_version'    => $this->ruleset_version(),
				'matched_rule_count' => $count,
			),
		);
	}

	/**
	 * Uses urldecode(), not rawurldecode(): the subject is a mix of request
	 * path and query string, and a query string's "+" conventionally means
	 * a literal space (how PHP itself populates $_GET, and how every
	 * browser encodes a space typed into a GET <form>, e.g. a search box --
	 * rawurldecode() would leave "union+select+committee" with literal "+"
	 * characters, silently breaking whitespace-sensitive rules against
	 * exactly the ordinary traffic this phase most needs to stay quiet on.
	 */
	private static function decode( string $raw ): string {
		return urldecode( $raw );
	}

	private static function outranks( string $candidate, string $current ): bool {
		return ( self::SEVERITY_ORDER[ $candidate ] ?? 0 ) > ( self::SEVERITY_ORDER[ $current ] ?? 0 );
	}
}
