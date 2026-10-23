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
		$this->assertSame( '', $sealer->reveal( Sealer::PREFIX . str_repeat( 'A', 60 ) ), 'Never shows ciphertext as a value.' );
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

	/**
	 * Anybody can type a value that starts `s1.`. Taken as sealed on the
	 * prefix alone, seal_once() stored it in the clear.
	 */
	public function test_a_plain_value_that_starts_like_a_sealed_one_is_still_sealed(): void {
		$sealer = $this->sealer();

		foreach ( array( 's1.', 's1.jordan', 's1.' . str_repeat( 'A', 54 ), 's1.' . str_repeat( 'A', 60 ) . "\n", 's1.' . str_repeat( 'A', 59 ) . '=' ) as $plain ) {
			$this->assertFalse( Sealer::sealed( $plain ) );
			$this->assertSame( $plain, $sealer->open( $sealer->seal_once( $plain ) ) );
			$this->assertSame( $plain, $sealer->reveal( $plain ) );
		}

		$this->assertTrue( Sealer::sealed( $sealer->seal( 'x' ) ) );
	}

	public function test_dumping_it_does_not_print_the_key(): void {
		$this->assertStringContainsString( '[redacted]', print_r( $this->sealer(), true ) );
		$this->assertStringNotContainsString( self::SECRET, print_r( $this->sealer(), true ) );
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

	/* ─── Files (1.7.0) ─────────────────────────────────────────────── */

	private function tmp( string $name ): string {
		static $dir = null;
		$dir ??= sys_get_temp_dir() . '/sealer-' . bin2hex( random_bytes( 4 ) );
		if ( ! is_dir( $dir ) ) {
			mkdir( $dir );
		}

		return $dir . '/' . $name;
	}

	/**
	 * @return array<string, array{int}>
	 */
	public static function sizes(): array {
		return array(
			'empty'               => array( 0 ),
			'one byte'            => array( 1 ),
			'exactly one chunk'   => array( 65536 ),
			'chunk and a byte'    => array( 65537 ),
			'several chunks'      => array( 300_000 ),
		);
	}

	#[\PHPUnit\Framework\Attributes\DataProvider( 'sizes' )]
	public function test_a_file_round_trips( int $size ): void {
		$sealer = new Sealer( str_repeat( 'k', 32 ), 'backups' );
		$plain  = $this->tmp( "p$size" );
		file_put_contents( $plain, $size > 0 ? random_bytes( $size ) : '' );

		$sealer->seal_file( $plain, $this->tmp( "s$size" ) );
		$this->assertNotSame( file_get_contents( $plain ), file_get_contents( $this->tmp( "s$size" ) ) );
		$this->assertTrue( $sealer->open_file( $this->tmp( "s$size" ), $this->tmp( "o$size" ) ) );
		$this->assertSame( hash_file( 'sha256', $plain ), hash_file( 'sha256', $this->tmp( "o$size" ) ) );
	}

	public function test_a_tampered_cut_or_extended_file_does_not_open(): void {
		$sealer = new Sealer( str_repeat( 'k', 32 ), 'backups' );
		file_put_contents( $this->tmp( 'p' ), random_bytes( 200_000 ) );
		$sealer->seal_file( $this->tmp( 'p' ), $this->tmp( 's' ) );
		$sealed = (string) file_get_contents( $this->tmp( 's' ) );

		$cases = array(
			'a flipped byte'      => substr_replace( $sealed, chr( ord( $sealed[100_000] ) ^ 1 ), 100_000, 1 ),
			'cut at a chunk'      => substr( $sealed, 0, 8 + 24 + 65536 + 17 ),
			'cut short'           => substr( $sealed, 0, -10 ),
			'bytes added'         => $sealed . 'x',
			'not a sealed file'   => 'hello',
		);

		foreach ( $cases as $name => $bytes ) {
			file_put_contents( $this->tmp( 'bad' ), $bytes );
			$this->assertFalse( $sealer->open_file( $this->tmp( 'bad' ), $this->tmp( 'out' ) ), $name );
			$this->assertFileDoesNotExist( $this->tmp( 'out' ), "$name leaves nothing behind" );
		}
	}

	public function test_another_key_or_context_cannot_open_a_file(): void {
		file_put_contents( $this->tmp( 'p' ), 'secret database' );
		( new Sealer( str_repeat( 'k', 32 ), 'backups' ) )->seal_file( $this->tmp( 'p' ), $this->tmp( 's' ) );

		$this->assertFalse( ( new Sealer( str_repeat( 'j', 32 ), 'backups' ) )->open_file( $this->tmp( 's' ), $this->tmp( 'o' ) ) );
		$this->assertFalse( ( new Sealer( str_repeat( 'k', 32 ), 'other' ) )->open_file( $this->tmp( 's' ), $this->tmp( 'o' ) ) );
		$this->assertNull( ( new Sealer( str_repeat( 'k', 32 ), 'backups' ) )->open( (string) file_get_contents( $this->tmp( 's' ) ) ), 'and open() is a different format' );
	}

	public function test_sealing_a_large_file_does_not_hold_it_in_memory(): void {
		$sealer = new Sealer( str_repeat( 'k', 32 ), 'backups' );
		$plain  = $this->tmp( 'big' );
		$handle = fopen( $plain, 'wb' );
		for ( $i = 0; $i < 64; $i++ ) {
			fwrite( $handle, random_bytes( 262_144 ) );
		}
		fclose( $handle );

		$before = memory_get_usage();
		$sealer->seal_file( $plain, $this->tmp( 'big.sealed' ) );
		$this->assertTrue( $sealer->open_file( $this->tmp( 'big.sealed' ), $this->tmp( 'big.out' ) ) );
		$this->assertLessThan( 2 * 1024 * 1024, memory_get_peak_usage() - $before, '16 MB through, well under 2 MB held' );
		$this->assertSame( filesize( $plain ), filesize( $this->tmp( 'big.out' ) ) );
	}

	public function test_a_missing_file_throws(): void {
		$this->expectException( \RuntimeException::class );

		( new Sealer( str_repeat( 'k', 32 ) ) )->seal_file( $this->tmp( 'nope' ), $this->tmp( 'x' ) );
	}
}
