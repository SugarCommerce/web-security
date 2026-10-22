<?php
/**
 * Reveal tests.
 *
 * @package SugarCommerce\WebSecurity\Tests
 */

declare( strict_types=1 );

namespace SugarCommerce\WebSecurity\Tests;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SugarCommerce\WebSecurity\Reveal;

/**
 * Class RevealTest
 */
final class RevealTest extends TestCase {

	private const string SECRET = 'a-token-secret-that-is-long-enough-to-seal';

	private const string LINK = 'https://shop.example.com/r/eyJhbGciOi.payload.signature';

	/**
	 * The cookie jar a browser would send back.
	 *
	 * @param array<string, scalar|null> $values
	 *
	 * @return array<string, string>
	 */
	private function jar( Reveal $reveal, array $values, string $name = 'reveal' ): array {
		$header = $reveal->cookie_header( $values, false );

		$this->assertSame( 1, preg_match( '/^' . preg_quote( $name, '/' ) . '=([^;]*);/', $header, $match ) );

		return array( $name => $match[1] );
	}

	public function test_values_round_trip(): void {
		$reveal = new Reveal( self::SECRET );
		$values = array( 'url' => self::LINK, 'customer' => 42, 'days' => 7, 'note' => 'café', 'ok' => true, 'none' => null );

		$this->assertSame( $values, @$reveal->take( $this->jar( $reveal, $values ) ) );
	}

	public function test_the_value_is_encrypted_not_just_signed(): void {
		$header = ( new Reveal( self::SECRET ) )->cookie_header( array( 'url' => self::LINK ), true );

		$this->assertStringNotContainsString( 'eyJhbGciOi', $header );
		$this->assertStringNotContainsString( base64_encode( self::LINK ), $header );
		$this->assertStringContainsString( '; Secure; HttpOnly; SameSite=Lax', $header );
	}

	public function test_it_is_shown_once_from_the_superglobal(): void {
		$reveal  = new Reveal( self::SECRET );
		$_COOKIE = $this->jar( $reveal, array( 'url' => self::LINK ) );

		$this->assertSame( array( 'url' => self::LINK ), @$reveal->take() );
		$this->assertNull( @$reveal->take() );
	}

	public function test_another_secret_cannot_open_it(): void {
		$jar = $this->jar( new Reveal( self::SECRET ), array( 'url' => self::LINK ) );

		$this->assertNull( @( new Reveal( self::SECRET . '-rotated' ) )->take( $jar ) );
	}

	public function test_a_tampered_cookie_is_refused(): void {
		$reveal = new Reveal( self::SECRET );
		$jar    = $this->jar( $reveal, array( 'url' => self::LINK ) );
		$last   = substr( $jar['reveal'], -1 );

		$jar['reveal'] = substr( $jar['reveal'], 0, -1 ) . ( 'A' === $last ? 'B' : 'A' );

		$this->assertNull( @$reveal->take( $jar ) );
	}

	public function test_an_expired_reveal_is_refused(): void {
		$reveal = new Reveal( self::SECRET, lifetime: 1 );
		$jar    = $this->jar( $reveal, array( 'url' => self::LINK ) );

		sleep( 2 );

		$this->assertNull( @$reveal->take( $jar ) );
	}

	/**
	 * @return array<string, array{mixed}>
	 */
	public static function junk(): array {
		return array(
			'plain text'   => array( 'hello' ),
			'empty'        => array( '' ),
			'sealed shape' => array( 's1.AAAA' ),
			'an array'     => array( array( 'x' ) ),
		);
	}

	#[DataProvider( 'junk' )]
	public function test_junk_is_refused( mixed $value ): void {
		$this->assertNull( @( new Reveal( self::SECRET ) )->take( array( 'reveal' => $value ) ) );
	}

	public function test_nothing_is_set_or_accepted_without_a_secret(): void {
		$this->assertSame( '', ( new Reveal( '' ) )->cookie_header( array( 'url' => self::LINK ), false ) );

		$jar = $this->jar( new Reveal( self::SECRET ), array( 'url' => self::LINK ) );
		$this->assertNull( @( new Reveal( '' ) )->take( $jar ) );
	}

	public function test_the_cookie_name_and_path_are_used(): void {
		$header = ( new Reveal( self::SECRET, 'fv_reveal', '/admin', 30 ) )->cookie_header( array( 'a' => 1 ), false );

		$this->assertStringStartsWith( 'fv_reveal=s1.', $header );
		$this->assertStringContainsString( '; Max-Age=30; Path=/admin; HttpOnly; SameSite=Lax', $header );
		$this->assertStringStartsWith( 'fv_reveal=;', ( new Reveal( self::SECRET, 'fv_reveal', '/admin' ) )->clear_header() );
	}

	public function test_a_value_that_is_not_scalar_is_refused(): void {
		$this->expectException( \InvalidArgumentException::class );

		( new Reveal( self::SECRET ) )->cookie_header( array( 'list' => array( 1, 2 ) ), false );
	}

	public function test_an_oversized_reveal_is_refused(): void {
		$this->expectException( \InvalidArgumentException::class );

		( new Reveal( self::SECRET ) )->cookie_header( array( 'big' => str_repeat( 'x', Reveal::MAX_BYTES ) ), false );
	}

	/**
	 * @return array<string, array{string, string, string, int}>
	 */
	public static function bad_settings(): array {
		return array(
			'short secret'   => array( 'short', 'reveal', '/', 60 ),
			'bad name'       => array( self::SECRET, 'a b', '/', 60 ),
			'bad path'       => array( self::SECRET, 'reveal', 'admin', 60 ),
			'path attribute' => array( self::SECRET, 'reveal', '/; Domain=evil', 60 ),
			'no lifetime'    => array( self::SECRET, 'reveal', '/', 0 ),
		);
	}

	#[DataProvider( 'bad_settings' )]
	public function test_bad_settings_are_refused( string $secret, string $cookie, string $path, int $lifetime ): void {
		$this->expectException( \InvalidArgumentException::class );

		new Reveal( $secret, $cookie, $path, $lifetime );
	}

	public function test_the_key_is_not_dumped(): void {
		$this->assertStringNotContainsString( self::SECRET, print_r( new Reveal( self::SECRET ), true ) );
	}
}
