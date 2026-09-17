<?php
/**
 * Session tests.
 *
 * @package SugarCommerce\WebSecurity\Tests
 */

declare( strict_types=1 );

namespace SugarCommerce\WebSecurity\Tests;

use PHPUnit\Framework\TestCase;
use SugarCommerce\SignedTokens\{Reason, Token};
use SugarCommerce\WebSecurity\Session;

/**
 * Class SessionTest
 */
final class SessionTest extends TestCase {

	private const PASSWORD = 'correct-horse-battery-staple';

	public function test_an_issued_session_is_valid(): void {
		$session = new Session( self::PASSWORD );

		$this->assertTrue( $session->valid( $session->issue() ) );
	}

	public function test_an_empty_cookie_is_not_a_session(): void {
		$session = new Session( self::PASSWORD );

		$this->assertFalse( $session->valid( '' ) );
	}

	public function test_rubbish_is_not_a_session(): void {
		$session = new Session( self::PASSWORD );

		$this->assertFalse( $session->valid( 'nonsense' ) );
		$this->assertFalse( $session->valid( 'operator:9999999999.deadbeef' ) );
	}

	public function test_a_session_from_another_password_does_not_verify(): void {
		$mine   = new Session( self::PASSWORD );
		$theirs = new Session( 'some-other-password' );

		$this->assertFalse( $mine->valid( $theirs->issue() ) );
	}

	public function test_rotating_the_password_ends_every_session(): void {
		$before = new Session( self::PASSWORD );
		$cookie = $before->issue();

		$this->assertFalse( ( new Session( 'rotated-password-value' ) )->valid( $cookie ) );
	}

	public function test_a_session_expires(): void {
		$issued  = new Session( self::PASSWORD, lifetime: 60, timestamp: 1_000_000 );
		$cookie  = $issued->issue();
		$later   = new Session( self::PASSWORD, lifetime: 60, timestamp: 1_000_061 );

		$this->assertFalse( $later->valid( $cookie ) );
		$this->assertSame( Reason::Expired, $later->read( $cookie ) );
	}

	public function test_a_session_is_valid_up_to_its_expiry(): void {
		$issued = new Session( self::PASSWORD, lifetime: 60, timestamp: 1_000_000 );
		$cookie = $issued->issue();

		$this->assertTrue( ( new Session( self::PASSWORD, lifetime: 60, timestamp: 1_000_059 ) )->valid( $cookie ) );
	}

	public function test_a_forged_cookie_never_reports_as_expired(): void {
		// Reporting expiry before checking the signature would tell a forger
		// they had the structure right.
		$session = new Session( self::PASSWORD, timestamp: 1_000_000 );

		$this->assertNotSame( Reason::Expired, $session->read( 'not.a.token' ) );
	}

	public function test_another_subject_cannot_present_its_cookie(): void {
		$operator = new Session( self::PASSWORD, subject: 'operator' );
		$support  = new Session( self::PASSWORD, subject: 'support' );

		$this->assertFalse( $operator->valid( $support->issue() ) );
	}

	public function test_read_returns_the_token_on_success(): void {
		$session = new Session( self::PASSWORD );

		$this->assertInstanceOf( Token::class, $session->read( $session->issue() ) );
	}

	public function test_a_session_carries_its_claims(): void {
		$session = new Session( self::PASSWORD );
		$token   = $session->read( $session->issue( array( 'e' => 'jordan@example.com' ) ) );

		$this->assertInstanceOf( Token::class, $token );
		$this->assertSame( 'jordan@example.com', $token->get( 'e' ) );
	}

	/**
	 * Otherwise a caller holding one role's session could mint another's.
	 */
	public function test_claims_cannot_overwrite_the_subject(): void {
		$session = new Session( self::PASSWORD, subject: 'buyer' );
		$cookie  = $session->issue( array( 'sub' => 'operator' ) );

		$this->assertFalse( ( new Session( self::PASSWORD, subject: 'operator' ) )->valid( $cookie ) );
		$this->assertTrue( $session->valid( $cookie ) );
	}

	public function test_claims_are_signed_with_the_rest(): void {
		$session = new Session( self::PASSWORD );
		$cookie  = $session->issue( array( 'e' => 'jordan@example.com' ) );

		// Swap the payload for one that claims a different address, keeping
		// the signature. A claim the holder can edit is not a claim.
		[ , $signature ] = explode( '.', $cookie, 2 ) + array( '', '' );
		$forged          = strtr( base64_encode( (string) json_encode( array( 'sub' => 'operator', 'e' => 'sydney@example.com' ) ) ), '+/', '-_' );

		$this->assertFalse( $session->valid( rtrim( $forged, '=' ) . '.' . $signature ) );
	}

	public function test_with_no_password_nothing_is_configured(): void {
		$session = new Session( '' );

		$this->assertFalse( $session->configured() );
		$this->assertFalse( $session->valid( 'anything' ) );
		$this->assertFalse( $session->authenticate( 'anything' ) );
	}

	public function test_with_no_password_issuing_is_a_programming_error(): void {
		$this->expectException( \LogicException::class );

		( new Session( '' ) )->issue();
	}

	public function test_authenticate_accepts_the_password(): void {
		$this->assertTrue( ( new Session( self::PASSWORD ) )->authenticate( self::PASSWORD ) );
	}

	public function test_authenticate_rejects_an_empty_submission(): void {
		$this->assertFalse( ( new Session( self::PASSWORD ) )->authenticate( '' ) );
	}

	public function test_the_cookie_is_httponly_and_strict(): void {
		$options = ( new Session( self::PASSWORD ) )->cookie_options( true, '/admin' );

		$this->assertTrue( $options['httponly'] );
		$this->assertTrue( $options['secure'] );
		$this->assertSame( 'Strict', $options['samesite'] );
		$this->assertSame( '/admin', $options['path'] );
	}

	public function test_the_cookie_is_not_marked_secure_over_plain_http(): void {
		// Marking it secure on a local host means the browser drops it and
		// the login form appears to do nothing at all.
		$this->assertFalse( ( new Session( self::PASSWORD ) )->cookie_options( false )['secure'] );
	}

	public function test_clearing_uses_the_same_path(): void {
		$this->assertSame( '/admin', Session::clear_options( '/admin' )['path'] );
		$this->assertSame( 1, Session::clear_options()['expires'] );
	}

	public function test_the_signing_key_is_not_the_password(): void {
		// Anything that leaked the key must not hand over the credential.
		$cookie = ( new Session( self::PASSWORD ) )->issue();

		$this->assertStringNotContainsString( self::PASSWORD, $cookie );
	}
}
