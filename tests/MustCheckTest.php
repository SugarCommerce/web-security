<?php
/**
 * Results that must not be ignored.
 *
 * @package   SugarCommerce\WebSecurity
 * @copyright Copyright (c) 2026, ArrayPress Limited
 * @license   GPL-2.0-or-later
 */

declare( strict_types=1 );

namespace SugarCommerce\WebSecurity\Tests;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SugarCommerce\WebSecurity\{Csrf, FormGuard, Hash, MagicLink, Sealer, Session};

/**
 * Class MustCheckTest
 *
 * These answer "did it work?" or "is it allowed?", and code that ignores the
 * answer behaves as though it were yes. #[\NoDiscard] makes PHP warn where a
 * result is dropped; this keeps the attribute from being lost in a refactor.
 */
final class MustCheckTest extends TestCase {

	/**
	 * @return array<string, array{string}>
	 */
	public static function methods(): array {
		return array(
			'Session::valid'        => array( Session::class . '::valid' ),
			'Session::read'         => array( Session::class . '::read' ),
			'Session::authenticate' => array( Session::class . '::authenticate' ),
			'Csrf::verify'          => array( Csrf::class . '::verify' ),
			'Hash::matches'         => array( Hash::class . '::matches' ),
			'Sealer::open'          => array( Sealer::class . '::open' ),
			'Sealer::reseal'        => array( Sealer::class . '::reseal' ),
			'Csrf::same_origin'     => array( Csrf::class . '::same_origin' ),
			'FormGuard::human'      => array( FormGuard::class . '::human' ),
			'FormGuard::trapped'    => array( FormGuard::class . '::trapped' ),
			'MagicLink::redeem'     => array( MagicLink::class . '::redeem' ),
			'MagicLink::read'       => array( MagicLink::class . '::read' ),
		);
	}

	#[DataProvider( 'methods' )]
	public function test_the_result_must_be_used( string $method ): void {
		$attributes = \ReflectionMethod::createFromMethodName( $method )->getAttributes( \NoDiscard::class );

		$this->assertCount( 1, $attributes, $method . ' lost #[\NoDiscard].' );
		$this->assertNotSame( '', $attributes[0]->newInstance()->message, 'Say why it matters.' );
	}
}
