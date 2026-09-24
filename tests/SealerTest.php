<?php
/**
 * Sealer test suite.
 *
 * @package   SugarCommerce\WebSecurity
 * @copyright Copyright (c) 2026, ArrayPress Limited
 * @license   GPL-2.0-or-later
 * @since     1.2.0
 */

declare( strict_types=1 );

namespace SugarCommerce\WebSecurity\Tests;

use PHPUnit\Framework\TestCase;
use SugarCommerce\WebSecurity\Sealer;

final class SealerTest extends TestCase {

	private const SECRET = 'a-secret-that-is-at-least-thirty-two-bytes';

	private function sealer( string $context = 'emails', string $secret = self::SECRET ): Sealer {
		return new Sealer( $secret, $context );
	}

	public function test_a_sealed_value_opens(): void {
		$sealed = $this->sealer()->seal( 'buyer@example.com' );

		$this->assertStringStartsWith( Sealer::PREFIX, $sealed );
		$this->assertStringNotContainsString( 'buyer', $sealed );
		$this->assertSame( 'buyer@example.com', $this->sealer()->open( $sealed ) );
	}

	/**
	 * A fresh nonce every time: two seals of one address must not match, or
	 * the ciphertext would be a lookup table.
	 */
	public function test_sealing_twice_gives_two_different_values(): void {
		$this->assertNotSame( $this->sealer()->seal( 'a@example.com' ), $this->sealer()->seal( 'a@example.com' ) );
	}

	public function test_another_key_or_context_cannot_open_it(): void {
		$sealed = $this->sealer()->seal( 'a@example.com' );

		$this->assertNull( $this->sealer( secret: str_repeat( 'x', 40 ) )->open( $sealed ) );
		$this->assertNull( $this->sealer( 'payloads' )->open( $sealed ) );
	}

	public function test_a_tampered_value_does_not_open(): void {
		$sealed   = $this->sealer()->seal( 'a@example.com' );
		$tampered = substr( $sealed, 0, -2 ) . ( 'A' === $sealed[-2] ? 'B' : 'A' ) . $sealed[-1];

		$this->assertNull( $this->sealer()->open( $tampered ) );
		$this->assertNull( $this->sealer()->open( Sealer::PREFIX . '!!!' ) );
		$this->assertNull( $this->sealer()->open( Sealer::PREFIX ) );
	}

	public function test_nothing_seals_to_nothing(): void {
		$this->assertSame( '', $this->sealer()->seal( '' ) );
	}

	/**
	 * A column part-way through being sealed reads both ways.
	 */
	public function test_reveal_opens_sealed_and_passes_the_rest(): void {
		$sealer = $this->sealer();

		$this->assertSame( 'a@example.com', $sealer->reveal( $sealer->seal( 'a@example.com' ) ) );
		$this->assertSame( 'plain@example.com', $sealer->reveal( 'plain@example.com' ) );
		$this->assertNull( $sealer->reveal( null ) );
		$this->assertSame( 42, $sealer->reveal( 42 ) );
		$this->assertSame( '', $sealer->reveal( Sealer::PREFIX . 'garbage' ), 'Never shows ciphertext as a value.' );
	}

	public function test_a_short_secret_is_refused(): void {
		$this->expectException( \InvalidArgumentException::class );

		new Sealer( 'short' );
	}
}
