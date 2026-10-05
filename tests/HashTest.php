<?php
/**
 * Hash tests.
 *
 * @package SugarCommerce\WebSecurity\Tests
 */

declare( strict_types=1 );

namespace SugarCommerce\WebSecurity\Tests;

use PHPUnit\Framework\TestCase;
use SugarCommerce\WebSecurity\Hash;

/**
 * Class HashTest
 */
final class HashTest extends TestCase {

	private Hash $hash;

	protected function setUp(): void {
		$this->hash = new Hash( 'a-secret-at-least-this-long' );
	}

	public function test_the_same_address_always_gives_the_same_digest(): void {
		$this->assertSame( $this->hash->ip( '1.2.3.4' ), $this->hash->ip( '1.2.3.4' ) );
	}

	public function test_different_addresses_give_different_digests(): void {
		$this->assertNotSame( $this->hash->ip( '1.2.3.4' ), $this->hash->ip( '1.2.3.5' ) );
	}

	public function test_a_different_secret_gives_a_different_digest(): void {
		$other = new Hash( 'a-different-secret-entirely' );

		$this->assertNotSame( $this->hash->ip( '1.2.3.4' ), $other->ip( '1.2.3.4' ) );
	}

	public function test_an_empty_value_hashes_to_nothing(): void {
		// Not to a digest of the empty string, which would compare equal
		// across every row that had no address.
		$this->assertSame( '', $this->hash->ip( '' ) );
		$this->assertSame( '', $this->hash->opaque( '' ) );
	}

	public function test_the_digest_is_hex(): void {
		$this->assertMatchesRegularExpression( '/^[a-f0-9]{64}$/', $this->hash->ip( '1.2.3.4' ) );
	}

	public function test_ip_and_opaque_share_one_keyspace(): void {
		// Documented rather than incidental: a caller that hashes an address
		// with opaque() must still find it.
		$this->assertSame( $this->hash->ip( '1.2.3.4' ), $this->hash->opaque( '1.2.3.4' ) );
	}

	public function test_matches_compares_against_a_stored_digest(): void {
		$digest = $this->hash->opaque( 'jordan@example.com' );

		$this->assertTrue( $this->hash->matches( 'jordan@example.com', $digest ) );
		$this->assertFalse( $this->hash->matches( 'someone@example.com', $digest ) );
	}

	public function test_matches_refuses_an_empty_digest(): void {
		$this->assertFalse( $this->hash->matches( '', '' ) );
		$this->assertFalse( $this->hash->matches( 'anything', '' ) );
	}

	/* ─── Derived keys ─────────────────────────────────────────────────── */

	/**
	 * The same key HKDF gives by hand, so digests stored before this
	 * method existed still match.
	 */
	public function test_a_derived_hash_is_keyed_by_hkdf(): void {
		$by_hand = new Hash( hash_hkdf( 'sha256', 'shared-secret', 32, 'app/email-index' ) );

		$this->assertSame( $by_hand->opaque( 'a@example.com' ), Hash::derived( 'shared-secret', 'app/email-index' )->opaque( 'a@example.com' ) );
	}

	public function test_two_contexts_never_compare_equal(): void {
		$this->assertNotSame(
			Hash::derived( 'shared-secret', 'app/email-index' )->opaque( 'a@example.com' ),
			Hash::derived( 'shared-secret', 'app/rate-limit' )->opaque( 'a@example.com' )
		);
		$this->assertNotSame( ( new Hash( 'shared-secret' ) )->opaque( 'x' ), Hash::derived( 'shared-secret', 'c' )->opaque( 'x' ) );
	}
}
