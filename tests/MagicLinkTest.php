<?php
/**
 * MagicLink test suite.
 *
 * @package   SugarCommerce\WebSecurity
 * @copyright Copyright (c) 2026, ArrayPress Limited
 * @license   GPL-2.0-or-later
 * @since     1.3.0
 */

declare( strict_types=1 );

namespace SugarCommerce\WebSecurity\Tests;

use PHPUnit\Framework\TestCase;
use SugarCommerce\SignedTokens\{Reason, Token, TokenSigner};
use SugarCommerce\WebSecurity\{MagicLink, Session};

/**
 * Class MagicLinkTest
 *
 * The link and the session it starts must never stand in for each other.
 */
final class MagicLinkTest extends TestCase {

	private const string SECRET = 'a-secret-that-is-at-least-thirty-two-bytes';

	private const int NOW = 1_800_000_000;

	private static function link( int $now = self::NOW, ?TokenSigner $signer = null ): MagicLink {
		return new MagicLink(
			$signer ?? new TokenSigner( self::SECRET, timestamp: $now ),
			new Session( self::SECRET, subject: 'buyer', timestamp: $now ),
			'buyer-purchases',
			600
		);
	}

	public function test_a_link_carries_its_claims(): void {
		$token = self::link()->redeem( self::link()->link( array( 'e' => 'a@example.com' ) ) );

		$this->assertInstanceOf( Token::class, $token );
		$this->assertSame( 'a@example.com', $token->get( 'e' ) );
	}

	public function test_a_link_expires(): void {
		$link = self::link()->link( array( 'e' => 'a@example.com' ) );

		$this->assertSame( Reason::Expired, self::link( self::NOW + 601 )->redeem( $link ) );
	}

	public function test_a_session_reads_back_its_claims(): void {
		$token = self::link()->read( self::link()->issue( array( 'e' => 'a@example.com' ) ) );

		$this->assertInstanceOf( Token::class, $token );
		$this->assertSame( 'a@example.com', $token->get( 'e' ) );
	}

	/**
	 * The long-lived cookie pasted into the sign-in URL is not a link, and
	 * a forwarded link is not a session.
	 */
	public function test_a_session_is_not_a_link_and_a_link_is_not_a_session(): void {
		$magic = self::link();

		$this->assertNotInstanceOf( Token::class, $magic->redeem( $magic->issue( array( 'e' => 'a@example.com' ) ) ) );
		$this->assertNotInstanceOf( Token::class, $magic->read( $magic->link( array( 'e' => 'a@example.com' ) ) ) );
	}

	public function test_a_link_cannot_be_signed_as_a_session(): void {
		$this->expectException( \InvalidArgumentException::class );

		new MagicLink( null, new Session( self::SECRET ), 'web-security.session' );
	}

	public function test_without_a_signer_nothing_is_signed_or_accepted(): void {
		$magic = new MagicLink( null, new Session( self::SECRET ) );

		$this->assertFalse( $magic->configured() );
		$this->assertSame( '', $magic->link( array( 'e' => 'a@example.com' ) ) );
		$this->assertSame( Reason::Malformed, $magic->redeem( self::link()->link( array( 'e' => 'a@example.com' ) ) ) );
		$this->assertTrue( self::link()->configured() );
	}

	public function test_the_cookie_options_are_the_sessions(): void {
		$options = self::link()->cookie_options( true, '/orders' );

		$this->assertSame( '/orders', $options['path'] );
		$this->assertTrue( $options['secure'] );
		$this->assertTrue( $options['httponly'] );
	}
}
