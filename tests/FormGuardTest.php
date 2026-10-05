<?php
/**
 * FormGuard test suite.
 *
 * @package   SugarCommerce\WebSecurity
 * @copyright Copyright (c) 2026, ArrayPress Limited
 * @license   GPL-2.0-or-later
 * @since     1.3.0
 */

declare( strict_types=1 );

namespace SugarCommerce\WebSecurity\Tests;

use PHPUnit\Framework\TestCase;
use SugarCommerce\SignedTokens\TokenSigner;
use SugarCommerce\WebSecurity\FormGuard;

/**
 * Class FormGuardTest
 *
 * Too fast is a script, too late is a replay, and a stamp is only good for
 * the form it was drawn for.
 */
final class FormGuardTest extends TestCase {

	private const string SECRET = 'a-secret-that-is-at-least-thirty-two-bytes';

	private const int NOW = 1_800_000_000;

	private static function guard( int $now = self::NOW, string $form = 'report', string $secret = self::SECRET ): FormGuard {
		return new FormGuard( new TokenSigner( $secret, timestamp: self::NOW ), $form, now: $now );
	}

	public function test_a_form_sent_after_a_person_could_type_passes(): void {
		$stamp = self::guard()->stamp();

		$this->assertTrue( self::guard( self::NOW + 30 )->human( $stamp ) );
		$this->assertTrue( self::guard( self::NOW + FormGuard::MIN )->human( $stamp ) );
	}

	public function test_a_form_sent_too_quickly_fails(): void {
		$stamp = self::guard()->stamp();

		$this->assertFalse( self::guard()->human( $stamp ) );
		$this->assertFalse( self::guard( self::NOW + FormGuard::MIN - 1 )->human( $stamp ) );
	}

	public function test_a_stale_form_fails(): void {
		$this->assertFalse( self::guard( self::NOW + FormGuard::MAX )->human( self::guard()->stamp() ) );
	}

	public function test_a_stamp_from_another_form_or_key_fails(): void {
		$this->assertFalse( self::guard( self::NOW + 30, 'contact' )->human( self::guard()->stamp() ) );
		$this->assertFalse( self::guard( self::NOW + 30 )->human( self::guard( secret: str_repeat( 'x', 40 ) )->stamp() ) );
	}

	/**
	 * A backdated stamp is the obvious forgery: it is not signed.
	 */
	public function test_a_forged_or_missing_stamp_fails(): void {
		$this->assertFalse( self::guard()->human( ( self::NOW - 60 ) . '.deadbeef' ) );
		$this->assertFalse( self::guard()->human( '' ) );
	}

	public function test_the_trap_is_anything_but_blank(): void {
		$this->assertTrue( FormGuard::trapped( 'http://spam.example' ) );
		$this->assertFalse( FormGuard::trapped( '' ) );
		$this->assertFalse( FormGuard::trapped( "  \n" ) );
	}

	public function test_the_limits_can_be_changed(): void {
		$guard = new FormGuard( new TokenSigner( self::SECRET, timestamp: self::NOW ), 'quick', 0, 10, self::NOW );

		$this->assertTrue( $guard->human( $guard->stamp() ) );
	}
}
