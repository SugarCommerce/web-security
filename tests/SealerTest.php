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

	/* ─── Sealing once ─────────────────────────────────────────────────── */

	public function test_a_sealed_value_is_not_sealed_twice(): void {
		$sealer = $this->sealer();
		$sealed = $sealer->seal( 'a@example.com' );

		$this->assertSame( $sealed, $sealer->seal_once( $sealed ) );
		$this->assertSame( 'a@example.com', $sealer->open( $sealer->seal_once( 'a@example.com' ) ) );
		$this->assertSame( '', $sealer->seal_once( '' ) );
	}

	/* ─── Re-sealing ───────────────────────────────────────────────────── */

	public function test_a_value_under_an_old_key_moves_to_the_new_one(): void {
		$old   = $this->sealer( secret: str_repeat( 'o', 40 ) );
		$new   = $this->sealer();
		$moved = $new->reseal( $old->seal( 'a@example.com' ), $old );

		$this->assertSame( 'a@example.com', $new->open( (string) $moved ) );
		$this->assertNull( $old->open( (string) $moved ) );
	}

	/**
	 * A rotation that died part-way is finished by running it again.
	 */
	public function test_a_value_already_moved_is_moved_again_harmlessly(): void {
		$old = $this->sealer( secret: str_repeat( 'o', 40 ) );
		$new = $this->sealer();

		$this->assertSame( 'a@example.com', $new->open( (string) $new->reseal( $new->seal( 'a@example.com' ), $old ) ) );
	}

	public function test_a_plain_value_is_sealed_and_nothing_stays_nothing(): void {
		$new = $this->sealer();

		$this->assertSame( 'legacy@example.com', $new->open( (string) $new->reseal( 'legacy@example.com' ) ) );
		$this->assertSame( '', $new->reseal( '' ) );
	}

	/**
	 * Under a key nobody has: overwriting it would lose it.
	 */
	public function test_a_value_no_key_opens_is_refused(): void {
		$lost = $this->sealer( secret: str_repeat( 'z', 40 ) )->seal( 'a@example.com' );

		$this->assertNull( $this->sealer()->reseal( $lost, $this->sealer( secret: str_repeat( 'o', 40 ) ) ) );
	}
}
