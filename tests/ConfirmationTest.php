<?php
/**
 * Confirmation tests.
 *
 * @package SugarCommerce\WebSecurity\Tests
 */

declare( strict_types=1 );

namespace SugarCommerce\WebSecurity\Tests;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SugarCommerce\WebSecurity\Confirmation;

/**
 * Class ConfirmationTest
 */
final class ConfirmationTest extends TestCase {

	/**
	 * The cookie jar a browser would send back after start().
	 *
	 * @return array{0: array<string, string>, 1: string}
	 */
	private function started( Confirmation $confirm, string $name = 'confirm' ): array {
		[ 'nonce' => $nonce, 'cookie' => $line ] = $confirm->start( true );
		$this->assertSame( 1, preg_match( '/^' . preg_quote( $name, '/' ) . '=([^;]*);/', $line, $m ) );

		return array( array( $name => $m[1] ), $nonce );
	}

	public function test_the_posted_nonce_must_match_the_cookie(): void {
		$confirm           = new Confirmation();
		[ $jar, $nonce ]   = $this->started( $confirm );

		$this->assertTrue( $confirm->confirmed( $jar, $nonce ) );
		$this->assertFalse( $confirm->confirmed( $jar, strrev( $nonce ) ) );
		$this->assertFalse( $confirm->confirmed( array(), $nonce ), 'no cookie: another site, or expired' );
		$this->assertFalse( $confirm->confirmed( $jar, '' ) );
	}

	public function test_the_cookie_is_strict_httponly_and_short_lived(): void {
		$line = ( new Confirmation( 'fv_confirm', '/enter', 300 ) )->start( true )['cookie'];

		$this->assertStringStartsWith( 'fv_confirm=', $line );
		$this->assertStringContainsString( '; Max-Age=300; Path=/enter; Secure; HttpOnly; SameSite=Strict', $line );
		$this->assertStringContainsString( 'SameSite=Strict', ( new Confirmation() )->clear_header() );
	}

	public function test_each_start_is_a_new_nonce(): void {
		$confirm = new Confirmation();

		$this->assertNotSame( $confirm->start( false )['nonce'], $confirm->start( false )['nonce'] );
	}

	/**
	 * @return array<string, array{mixed}>
	 */
	public static function forged(): array {
		return array(
			'empty'      => array( '' ),
			'not hex'    => array( str_repeat( 'z', 32 ) ),
			'too short'  => array( 'abc' ),
			'an array'   => array( array( 'x' ) ),
		);
	}

	#[DataProvider( 'forged' )]
	public function test_a_forged_cookie_never_confirms( mixed $cookie ): void {
		$this->assertFalse( ( new Confirmation() )->confirmed( array( 'confirm' => $cookie ), is_string( $cookie ) ? $cookie : '' ) );
	}

	public function test_bad_settings_are_refused(): void {
		$this->expectException( \InvalidArgumentException::class );

		new Confirmation( 'confirm', '/', 0 );
	}
}
