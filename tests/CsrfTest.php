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

	/* ─── Where the token was put ──────────────────────────────────────── */

	public function test_the_token_is_found_in_a_form_a_json_body_or_a_header(): void {
		$this->assertSame( 'f', Csrf::submitted( array( Csrf::FIELD => 'f' ), 'h', array( Csrf::FIELD => 'j' ) ) );
		$this->assertSame( 'j', Csrf::submitted( array(), 'h', array( Csrf::FIELD => 'j' ) ) );
		$this->assertSame( 'h', Csrf::submitted( array(), 'h' ) );
		$this->assertSame( '', Csrf::submitted( array( Csrf::FIELD => array( 'not', 'a', 'token' ) ) ) );
	}

	/* ─── Same origin ──────────────────────────────────────────────────── */

	public function test_a_foreign_origin_is_refused_and_a_missing_one_is_no_evidence(): void {
		$this->assertTrue( Csrf::same_origin( 'https://shop.example', '', 'shop.example' ) );
		$this->assertTrue( Csrf::same_origin( '', 'https://shop.example/page?x=1', 'shop.example' ) );
		$this->assertTrue( Csrf::same_origin( '', '', 'shop.example' ) );
		$this->assertFalse( Csrf::same_origin( 'https://evil.example', '', 'shop.example' ) );
		$this->assertFalse( Csrf::same_origin( '', 'https://evil.example/', 'shop.example' ) );
	}

	public function test_origin_wins_over_referer(): void {
		$this->assertFalse( Csrf::same_origin( 'https://evil.example', 'https://shop.example/', 'shop.example' ) );
	}

	public function test_hosts_are_matched_exactly_with_their_port(): void {
		$this->assertFalse( Csrf::names_host( 'https://notshop.example', 'shop.example' ) );
		$this->assertFalse( Csrf::names_host( 'https://shop.example.evil.example', 'shop.example' ) );
		$this->assertFalse( Csrf::names_host( 'http://localhost:9000', 'localhost:8080' ) );
		$this->assertTrue( Csrf::names_host( 'http://LOCALHOST:8080', 'localhost:8080' ) );
		$this->assertFalse( Csrf::names_host( 'null', 'shop.example' ), 'A sandboxed frame names no host.' );
		$this->assertFalse( Csrf::same_origin( 'null', '', 'shop.example' ) );
	}
}
