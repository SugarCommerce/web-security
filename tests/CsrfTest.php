<?php
/**
 * Csrf tests.
 *
 * @package SugarCommerce\WebSecurity\Tests
 */

declare( strict_types=1 );

namespace SugarCommerce\WebSecurity\Tests;

use PHPUnit\Framework\TestCase;
use SugarCommerce\WebSecurity\Csrf;

/**
 * Class CsrfTest
 */
final class CsrfTest extends TestCase {

	private Csrf $csrf;

	protected function setUp(): void {
		$this->csrf = new Csrf( 'token-secret', 'admin_session' );
	}

	public function test_no_cookie_means_no_token(): void {
		$this->assertSame( '', $this->csrf->token( array() ) );
	}

	public function test_no_cookie_means_verification_always_fails(): void {
		// The dangerous reading of an empty token is "no check needed".
		$this->assertFalse( $this->csrf->verify( '', array() ) );
		$this->assertFalse( $this->csrf->verify( 'anything', array() ) );
	}

	public function test_a_token_verifies_against_its_own_cookie(): void {
		$cookies = array( 'admin_session' => 'cookie-value' );

		$this->assertTrue( $this->csrf->verify( $this->csrf->token( $cookies ), $cookies ) );
	}

	public function test_a_token_from_another_session_does_not_verify(): void {
		$mine   = array( 'admin_session' => 'mine' );
		$theirs = array( 'admin_session' => 'theirs' );

		$this->assertFalse( $this->csrf->verify( $this->csrf->token( $theirs ), $mine ) );
	}

	public function test_a_token_from_another_secret_does_not_verify(): void {
		$cookies = array( 'admin_session' => 'cookie-value' );
		$forged  = ( new Csrf( 'wrong-secret', 'admin_session' ) )->token( $cookies );

		$this->assertFalse( $this->csrf->verify( $forged, $cookies ) );
	}

	public function test_the_token_rotates_with_the_session(): void {
		$before = $this->csrf->token( array( 'admin_session' => 'first' ) );
		$after  = $this->csrf->token( array( 'admin_session' => 'second' ) );

		$this->assertNotSame( $before, $after );
	}

	public function test_the_field_escapes_its_value(): void {
		$field = $this->csrf->field( array( 'admin_session' => 'x' ) );

		$this->assertStringContainsString( 'name="_csrf"', $field );
		$this->assertStringNotContainsString( '<script', $field );
	}

	public function test_it_reads_the_cookie_name_it_was_given(): void {
		$this->assertSame( '', $this->csrf->token( array( 'some_other_cookie' => 'x' ) ) );
	}
}
