<?php
/**
 * Flash tests.
 *
 * @package SugarCommerce\WebSecurity\Tests
 */

declare( strict_types=1 );

namespace SugarCommerce\WebSecurity\Tests;

use PHPUnit\Framework\TestCase;
use SugarCommerce\WebSecurity\Flash;

/**
 * Class FlashTest
 */
final class FlashTest extends TestCase {

	private Flash $flash;

	protected function setUp(): void {
		$this->flash = new Flash( 'token-secret' );
	}

	/**
	 * The cookie jar a browser would send back after set().
	 *
	 * @return array<string, string>
	 */
	private function jar( Flash $flash, string $kind, string $message, string $name = 'flash' ): array {
		$header = $flash->cookie_header( $kind, $message, false );

		$this->assertSame( 1, preg_match( '/^' . preg_quote( $name, '/' ) . '=([^;]*);/', $header, $match ) );

		return array( $name => $match[1] );
	}

	/**
	 * The jar with its cookie's payload rewritten.
	 *
	 * @param array<string, string> $jar  From jar().
	 * @param mixed                 $data What the payload decodes to.
	 *
	 * @return array<string, string>
	 */
	private static function repacked( array $jar, mixed $data ): array {
		$signature = substr( $jar['flash'], (int) strrpos( $jar['flash'], '.' ) + 1 );
		$payload   = rtrim( strtr( base64_encode( (string) json_encode( $data ) ), '+/', '-_' ), '=' );

		return array( 'flash' => $payload . '.' . $signature );
	}

	public function test_a_message_round_trips(): void {
		$this->assertSame(
			array( 'kind' => 'ok', 'message' => 'Refund sent.' ),
			$this->flash->take( $this->jar( $this->flash, 'ok', 'Refund sent.' ) )
		);
	}

	public function test_unicode_round_trips(): void {
		$this->assertSame( 'Café — 支払い済み', $this->flash->take( $this->jar( $this->flash, 'err', 'Café — 支払い済み' ) )['message'] ?? null );
	}

	public function test_the_cookie_is_first_party_and_short_lived(): void {
		$header = $this->flash->cookie_header( 'ok', 'Saved.', true );

		$this->assertMatchesRegularExpression( '/; Max-Age=(29|30);/', $header );
		$this->assertStringContainsString( '; Expires=', $header );
		$this->assertStringContainsString( '; Path=/', $header );
		$this->assertStringContainsString( '; Secure', $header );
		$this->assertStringContainsString( '; HttpOnly', $header );
		$this->assertStringContainsString( '; SameSite=Lax', $header );
		$this->assertStringNotContainsString( 'Saved', $header );
	}

	public function test_secure_follows_the_request(): void {
		$this->assertStringNotContainsString( 'Secure', $this->flash->cookie_header( 'ok', 'Saved.', false ) );
	}

	public function test_the_cookie_name_path_and_lifetime_are_used(): void {
		$flash  = new Flash( 'token-secret', 'notice', '/admin', 60 );
		$header = $flash->cookie_header( 'ok', 'Saved.', false );

		$this->assertStringStartsWith( 'notice=', $header );
		$this->assertStringContainsString( '; Path=/admin', $header );
		$this->assertMatchesRegularExpression( '/; Max-Age=(59|60);/', $header );
		$this->assertSame( 'Saved.', $flash->take( $this->jar( $flash, 'ok', 'Saved.', 'notice' ) )['message'] ?? null );
	}

	public function test_clear_header_expires_it_at_the_same_path(): void {
		$header = ( new Flash( 'token-secret', 'notice', '/admin' ) )->clear_header( true );

		$this->assertStringStartsWith( 'notice=; Expires=Thu, 01 Jan 1970 00:00:01 GMT; Max-Age=0', $header );
		$this->assertStringContainsString( '; Path=/admin', $header );
		$this->assertStringContainsString( '; Secure', $header );
	}

	public function test_no_cookie_is_no_message(): void {
		$this->assertNull( $this->flash->take( array() ) );
	}

	public function test_a_tampered_kind_is_refused(): void {
		$jar = $this->jar( $this->flash, 'ok', 'Refund sent.' );

		$this->assertNull( $this->flash->take( self::repacked( $jar, array( 'err', 'Refund sent.', time() + 30 ) ) ) );
	}

	public function test_a_tampered_message_is_refused(): void {
		$jar = $this->jar( $this->flash, 'ok', 'Refund sent.' );

		$this->assertNull( $this->flash->take( self::repacked( $jar, array( 'ok', 'Refund NOT sent.', time() + 30 ) ) ) );
	}

	public function test_a_tampered_signature_is_refused(): void {
		$jar   = $this->jar( $this->flash, 'ok', 'Refund sent.' );
		$value = $jar['flash'];
		$last  = substr( $value, -1 );

		$this->assertNull( $this->flash->take( array( 'flash' => substr( $value, 0, -1 ) . ( '0' === $last ? '1' : '0' ) ) ) );
		$this->assertNull( $this->flash->take( array( 'flash' => substr( $value, 0, (int) strrpos( $value, '.' ) ) ) ) );
		$this->assertNull( $this->flash->take( array( 'flash' => substr( $value, 0, (int) strrpos( $value, '.' ) ) . '.' ) ) );
	}

	public function test_another_secret_is_refused(): void {
		$this->assertNull( $this->flash->take( $this->jar( new Flash( 'other-secret' ), 'ok', 'Refund sent.' ) ) );
	}

	/**
	 * The key is derived under its own context, so a signature made with
	 * the bare secret — what Hash::opaque() or anything else keyed with it
	 * produces — is no flash signature.
	 */
	public function test_a_signature_with_the_bare_secret_is_refused(): void {
		$payload = rtrim( strtr( base64_encode( (string) json_encode( array( 'ok', 'Forged.', time() + 30 ) ) ), '+/', '-_' ), '=' );

		$this->assertNull( $this->flash->take( array( 'flash' => $payload . '.' . hash_hmac( 'sha256', $payload, 'token-secret' ) ) ) );
	}

	public function test_an_array_cookie_is_refused(): void {
		$this->assertNull( $this->flash->take( array( 'flash' => array( 'x' ) ) ) );
	}

	public function test_garbage_is_refused(): void {
		foreach ( array( '', '.', 'abc', 'abc.def', '!!!.' . str_repeat( 'a', 64 ) ) as $value ) {
			$this->assertNull( $this->flash->take( array( 'flash' => $value ) ) );
		}
	}

	public function test_an_unknown_kind_becomes_the_first(): void {
		$this->assertSame( 'ok', $this->flash->take( $this->jar( $this->flash, 'warning', 'Hmm.' ) )['kind'] ?? null );
		$this->assertSame( 'info', ( $flash = new Flash( 'token-secret', kinds: array( 'info', 'ok' ) ) )->take( $this->jar( $flash, 'nope', 'Hmm.' ) )['kind'] ?? null );
	}

	/**
	 * A kind dropped from the list since the message was set is not shown
	 * as something it is not.
	 */
	public function test_a_signed_kind_no_longer_known_is_refused(): void {
		$jar = $this->jar( new Flash( 'token-secret', kinds: array( 'warn' ) ), 'warn', 'Hmm.' );

		$this->assertNull( $this->flash->take( $jar ) );
	}

	public function test_line_breaks_and_control_characters_are_removed(): void {
		$taken = $this->flash->take( $this->jar( $this->flash, 'ok', "Line one\r\nSet-Cookie: x=1\x00\x07\x1B[31m\u{0085}" ) );

		$this->assertSame( 'Line one Set-Cookie: x=1[31m', $taken['message'] ?? null );
	}

	public function test_the_message_is_capped_in_characters_not_bytes(): void {
		$message = $this->flash->take( $this->jar( $this->flash, 'ok', str_repeat( '支', 250 ) ) )['message'] ?? '';

		$this->assertSame( Flash::MAX_LENGTH, preg_match_all( '/./u', $message ) );
		$this->assertSame( str_repeat( '支', Flash::MAX_LENGTH ), $message );
	}

	public function test_invalid_utf8_does_not_lose_the_message(): void {
		$this->assertSame( "Saved \u{FFFD}ok", $this->flash->take( $this->jar( $this->flash, 'ok', "Saved \xC3ok" ) )['message'] ?? null );
	}

	public function test_an_expired_message_is_refused(): void {
		// Signed with the real derived key, as a captured cookie replayed
		// after its expiry would be.
		$key = hash_hkdf( 'sha256', 'token-secret', 32, 'web-security/flash/v1' );

		foreach ( array( time() - 1 => null, time() + 30 => 'Old.' ) as $expires => $expected ) {
			$payload = rtrim( strtr( base64_encode( (string) json_encode( array( 'ok', 'Old.', $expires ) ) ), '+/', '-_' ), '=' );

			$this->assertSame( $expected, $this->flash->take( array( 'flash' => $payload . '.' . hash_hmac( 'sha256', $payload, $key ) ) )['message'] ?? null );
		}
	}

	public function test_an_empty_secret_sets_and_accepts_nothing(): void {
		$empty = new Flash( '' );

		$this->assertSame( '', $empty->cookie_header( 'ok', 'Saved.', false ) );
		$this->assertNull( $empty->take( $this->jar( $this->flash, 'ok', 'Saved.' ) ) );

		$payload = rtrim( strtr( base64_encode( (string) json_encode( array( 'ok', 'Forged.', time() + 30 ) ) ), '+/', '-_' ), '=' );

		$this->assertNull( $empty->take( array( 'flash' => $payload . '.' . hash_hmac( 'sha256', $payload, '' ) ) ) );
	}

	public function test_take_from_the_superglobal_is_one_shot(): void {
		$saved   = $_COOKIE;
		$_COOKIE = $this->jar( $this->flash, 'ok', 'Once.' );

		try {
			$this->assertSame( 'Once.', $this->flash->take()['message'] ?? null );
			$this->assertArrayNotHasKey( 'flash', $_COOKIE );
			$this->assertNull( $this->flash->take() );
		} finally {
			$_COOKIE = $saved;
		}
	}

	public function test_set_sends_without_complaint(): void {
		// header() is a no-op under the CLI; this proves only that nothing
		// throws or warns on the way there.
		$this->flash->set( 'ok', 'Saved.', false );
		( new Flash( '' ) )->set( 'ok', 'Saved.', false );

		$this->addToAssertionCount( 1 );
	}

	public function test_the_key_is_kept_out_of_dumps(): void {
		$dump = print_r( $this->flash, true );

		$this->assertStringContainsString( '[redacted]', $dump );
		$this->assertStringNotContainsString( 'token-secret', $dump );
		$this->assertStringNotContainsString( bin2hex( hash_hkdf( 'sha256', 'token-secret', 32, 'web-security/flash/v1' ) ), $dump );
	}

	public function test_a_bad_cookie_name_is_refused(): void {
		$this->expectException( \InvalidArgumentException::class );

		new Flash( 'token-secret', "flash\r\nX-Evil" );
	}

	public function test_a_bad_path_is_refused(): void {
		foreach ( array( 'admin', '/a;Secure', "/a\nb", '/a b' ) as $path ) {
			try {
				new Flash( 'token-secret', 'flash', $path );
				$this->fail( 'Accepted ' . json_encode( $path ) );
			} catch ( \InvalidArgumentException ) {
				$this->addToAssertionCount( 1 );
			}
		}
	}

	public function test_a_lifetime_under_a_second_is_refused(): void {
		$this->expectException( \InvalidArgumentException::class );

		new Flash( 'token-secret', lifetime: 0 );
	}

	public function test_no_kinds_is_refused(): void {
		$this->expectException( \InvalidArgumentException::class );

		new Flash( 'token-secret', kinds: array( '' ) );
	}
}
