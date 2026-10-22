# web-security

Signed-cookie sessions for a single shared password, passwordless sign-in
links, CSRF tokens with nothing to store, signed one-shot flash messages, bot
resistance for public forms without a captcha, sealing for values at rest, and
keyed hashing for the values an application has to compare but should never be
able to read back.

Seven small classes. No framework, no container, no middleware stack.

For cleaning and validating the input itself, see
[sanitize](https://github.com/sugarcommerce/sanitize), which this deliberately
does not depend on.

```bash
composer require sugarcommerce/web-security
```

## Hash

For values you have to store in order to count, compare or rate-limit, but have
no business being able to read back.

```php
use SugarCommerce\WebSecurity\Hash;

$hash = new Hash( $secret );

$hash->ip( $request_ip );         // store this, not the address
$hash->opaque( $user_agent );
$hash->matches( $ip, $stored );   // constant time
```

Keyed, and that is the entire point. IPv4 is four billion values, so an unkeyed
SHA-256 of an address is reversed by brute force in seconds — the digest is
still personal data, and storing it satisfies no data protection officer.
Keyed, it only ever compares equal to itself, which is all that counting
distinct visitors needs, and it is worthless to whoever takes the table without
the secret.

An empty value hashes to `''`, not to a digest of the empty string, which would
otherwise compare equal across every row that had no address. An empty
*secret* is refused with an exception: an HMAC under `''` is a hash anybody can
compute.

One configured secret, several purposes: derive a key per purpose rather than
keying every index with the secret itself, so an email's lookup hash never
equals its rate-limit key and rotating one is a decision about that one.

```php
$index = Hash::derived( $data_key, 'app/email-index' );   // HKDF-SHA256, stable
```

Not for API keys — those are looked up *by* their digest, so the digest cannot
depend on a secret the finder might not have; use
`SugarCommerce\Generate\Token::digest()`. Not for passwords either; those want
a slow hash.

## Session

One password, no users table.

```php
use SugarCommerce\WebSecurity\Session;

$session = new Session( $password, subject: 'operator' );

if ( $session->authenticate( $submitted ) ) {
    setcookie( Session::COOKIE, $session->issue(), $session->cookie_options( $is_https, '/admin' ) );
}

$session->valid( $_COOKIE[ Session::COOKIE ] ?? '' );
```

A session can carry claims — who it belongs to, rather than only which role it
is:

```php
$cookie = $session->issue( array( 'e' => 'jordan@example.com' ) );
$token  = $session->read( $cookie );

$token instanceof Token ? $token->get( 'e' ) : null;
```

They are signed with the rest of it, so the browser holding the cookie cannot
edit them — but they are not secret, and anybody with the cookie can read them.
A claim is an identifier, never a credential. `sub` is reserved and always wins,
so a caller cannot pass one to mint another role's session.

A signed cookie rather than a PHP session: nothing on disk to clean up, nothing
shared between workers, nothing to make sticky behind a load balancer. Rotating
the password ends every existing session for free, because the signing key is
derived from it.

To sign everyone out without changing the password, keep a generation — an
integer the application stores, a row in its settings table is enough — and
pass it in:

```php
$session = new Session( $password, subject: 'operator', generation: $settings->get( 'session_generation', 0 ) );

// Sign everyone out:
$settings->set( 'session_generation', $settings->get( 'session_generation', 0 ) + 1 );   // durable first
setcookie( Session::COOKIE, '', Session::clear_options( '/admin' ) );
```

The signing key is derived from the password and the generation together, so
incrementing it ends every session issued under the old one, exactly as
rotating the password would. Nothing about it is written into the cookie, so
there is nothing to edit: a cookie from an older generation is refused as a bad
signature — `Reason::InvalidSignature`, never `Expired` — before anything in it
is read. Make the increment durable before responding, or a crash in between
leaves every session it was meant to end still valid.

The key is HKDF-SHA256 of the password. Up to 1.3 it was an HMAC keyed with the
password over a fixed string — which is exactly what `Hash::opaque()` of that
string gives under the same secret, and what `Csrf::token()` printed for a
cookie set to it. An application that hands one secret to all three could be
made to show its session signing key. **Upgrading to 1.4.0 therefore signs
everybody out once.**

A captured cookie lets someone test password guesses offline, since the key is
a fast hash of the password. Where the password is one a person chose, give the
session a server-side secret too; guessing then needs it as well:

```php
$session = new Session( $password, secret: $token_secret );
```

The signing is [signed-tokens](https://github.com/sugarcommerce/signed-tokens)
rather than a hand-rolled HMAC, which buys two things beyond tidiness. The
signature is checked before the expiry, so a forged cookie can never come back
as "expired" and tell its forger the structure was right. And what is signed is
namespaced, so a token minted elsewhere in the same application can never be
presented as a session.

Where the difference is visible to the person, read the reason:

```php
use SugarCommerce\SignedTokens\Reason;

match ( true ) {
    $session->read( $cookie ) instanceof Token => $panel,
    Reason::Expired === $session->read( $cookie ) => 'Your session expired. Sign in again.',
    default => 'Sign in.',
};
```

Scope the cookie by path rather than leaving it at `/`. Where several surfaces
share one hostname, a root cookie is sent on every public request too — needless
exposure at best, and at worst it is what an XSS on a public page reaches for.

With no password set, `configured()` is false and every check fails closed. An
application may then fall back to something else — localhost-only access during
development is the usual one — but that is its decision to make explicitly.

## Csrf

```php
use SugarCommerce\WebSecurity\Csrf;

$csrf = new Csrf( $token_secret, Session::COOKIE );

echo $csrf->field();                       // hidden input, escaped

if ( ! $csrf->verify( $request->input( Csrf::FIELD ) ) ) {
    http_response_code( 403 );
}
```

The token is an HMAC of the session cookie under a server secret, so there is
nothing to store and nothing to expire separately: it rotates when the session
does, and a restarted server does not sign everyone out of their half-filled
forms.

That works because the cookie is HttpOnly — a malicious cross-origin page
cannot read it, so it cannot derive the token. `SameSite=Lax` alone is not
enough; it still permits top-level cross-origin POSTs in some browsers, which
is exactly the shape of a form-submit attack.

Key it on a general token secret rather than the password behind the session,
so rotating one does not silently invalidate the other. The HMAC is keyed with
a key derived from that secret, never with the secret itself: `token()` hashes
whatever cookie a request sends, signed in or not, and keyed with the bare
secret (as before 1.4) it was an oracle for every other keyed hash of it. The
change means tokens rendered before upgrading to 1.4.0 fail once. A cookie that
arrives as an array (`name[]=x`) has no token, and an empty secret gives none
either — every check fails.

Where the token arrived, and what the browser says about where the request came
from:

```php
$token = Csrf::submitted( $request->form, $request->header( Csrf::HEADER ), $request->json() );

if ( ! Csrf::same_origin( $request->header( 'origin' ), $request->header( 'referer' ), $request->host )
    || ! $csrf->verify( $token ) ) {
    http_response_code( 403 );
}
```

`submitted()` reads the form field, then a JSON body, then the header — never
the query string, where a token ends up in logs and Referer headers.
`same_origin()` is false only when Origin (or, failing that, Referer) names
another host, compared exactly with its port; their absence is not evidence,
so it is a first check beside `verify()`, never instead of it.

Exempt the login form. There is no session yet, and forging a login only forces
the victim to submit a password the attacker does not have.

An empty token means *always fail*, never *no check needed*. `verify()` already
reads it that way; anything calling `token()` directly has to make the same
choice.

## Flash messages

Post, redirect, get: the form handler does its work and redirects, and the page
it lands on says how it went. A `?saved=1` in the URL is one anybody can type
and link to — "Refund sent" on a page that refunded nothing — so the message
travels as a signed cookie instead.

```php
use SugarCommerce\WebSecurity\Flash;

$flash = new Flash( $token_secret ); // cookie 'flash', path '/', 30 seconds, kinds ok|err

// The handler
$flash->set( 'ok', 'Refund sent.', $is_https );
// …then redirect

// The page after
$message = $flash->take( secure: $is_https ); // array{kind, message}, or null

if ( null !== $message ) {
    printf( '<p class="flash-%s">%s</p>', $message['kind'], htmlspecialchars( $message['message'] ) );
}
```

The signature is an HMAC under a key derived from the secret with its own HKDF
context, never the secret itself, for the reason Csrf gives. The expiry is
inside what is signed, so a captured cookie stops working when it would have
expired whatever the browser was told. `take()` checks it in constant time and
returns null for anything missing, forged, tampered with, expired, malformed or
sent as an array — and clears the cookie whenever one was sent at all, good or
bad, so a message shows once. Reading from `$_COOKIE`, it removes it there too.

A kind not in the list becomes the first one. The message is plain text: line
breaks become spaces, control characters go, and it is cut to 200 characters
(not bytes). It is signed, not safe — escape it when you print it. An empty
secret sets nothing and accepts nothing. The cookie is HttpOnly and
`SameSite=Lax`; pass `$is_https` from the request, because a Secure cookie on a
plain-HTTP development host is dropped without a word.

`cookie_header()` and `clear_header()` give the Set-Cookie lines without
sending them, for tests and for a response object that carries its own headers.
Nothing here depends on one.

## Sealing values at rest

```php
use SugarCommerce\WebSecurity\{Hash, Sealer};

$sealer = new Sealer( $data_key, 'emails' );
$index  = new Hash( $data_key );

$row = array(
    'email'      => $sealer->seal( $email ),          // s1.… — useless without the key
    'email_hash' => $index->opaque( strtolower( $email ) ), // what lookups compare
);

$email = $sealer->reveal( $row['email'] );             // opens sealed, passes plain through
```

libsodium secretbox (authenticated), a fresh nonce per seal, a key derived per context. Keep the key in configuration, never beside the data: a stolen database or backup is then ciphertext. `reveal()` lets a column be sealed gradually — sealed values open, plain ones pass through, and a value that will not open reads as `''` rather than as ciphertext.

Moving to a new key, and writing values that may already be sealed:

```php
$new->reseal( $stored, $old );   // sealed under $old, $new or not at all → sealed under $new; null if no key opens it
$sealer->seal_once( $value );    // never seals a sealed value twice
```

`reseal()` is safe to run twice, so a rotation that dies part-way is finished
by running it again. Null means the value is under a key nobody has: stop
rather than overwrite it.

## Magic links

Passwordless sign-in: a short-lived link that is exchanged for a session.

```php
use SugarCommerce\WebSecurity\{MagicLink, Session};

$magic = new MagicLink( $signer, new Session( $secret, subject: 'buyer', lifetime: 2592000 ), 'buyer-link', ttl: 3600 );

$url = 'https://example.com/enter/' . $magic->link( array( 'e' => $email ) );

$token = $magic->redeem( $from_url );                     // Token, or a Reason
if ( $token instanceof Token ) {
    setcookie( 'buyer', $magic->issue( array( 'e' => $token->get( 'e' ) ) ), $magic->cookie_options( $is_https ) );
}

$magic->read( $_COOKIE['buyer'] ?? '' );                   // who is signed in
```

The link and the session are signed under different namespaces, so a long-lived
cookie pasted into the sign-in URL is not a link, and a forwarded link is not a
session. Not single-use on its own: mail scanners fetch every URL in a message
before the person clicks, and a link that burns on first fetch is spent before
it is used. Its short life is what limits it — and until then anybody holding
it can sign in.

Every link carries a random `jti` (`MagicLink::ID`, reserved) so it can be made
single-use without breaking scanners: have the link open a page that asks for
one click, and on that POST record the `jti` and refuse one already recorded.

```php
$token = $magic->redeem( $_POST['t'] ?? '' );

// INSERT OR IGNORE into your own table, keyed by jti; true when the row is new.
if ( $token instanceof Token && $spent->record( (string) $token->get( MagicLink::ID ) ) ) {
    setcookie( 'buyer', $magic->issue( array( 'e' => $token->get( 'e' ) ) ), $magic->cookie_options( $is_https ) );
}
```

## Public forms

A trap field and a signed stamp of when the form was drawn — most of what a
captcha catches, without sending every visitor to a third party.

```php
use SugarCommerce\WebSecurity\FormGuard;

$guard = new FormGuard( $signer, 'contact' );           // at least 3 seconds, at most a day

// Drawing: hidden inputs FormGuard::STAMP => $guard->stamp(), and an empty, hidden FormGuard::TRAP.

if ( FormGuard::trapped( $_POST[ FormGuard::TRAP ] ?? '' ) ) {
    return $thanks;                                      // a bot told it failed learns which field gave it away
}

if ( ! $guard->human( $_POST[ FormGuard::STAMP ] ?? '' ) ) {
    $problems['started'] = 'That was sent very quickly. Check it and send it again.';
}
```

The stamp is signed per form, so it cannot be backdated or carried to another
form. Neither check is a rate limit; put the form behind one as well.

## Testing

```bash
composer install
composer test
```

103 tests: sessions, their claims, their generations and their key derivation,
CSRF tokens and their derived key, where a token was submitted and same-origin
checks, keyed and derived hashing, sealing, sealing once and re-sealing across
keys, magic links, their identifiers and their separation from sessions, form stamps that are too fast, too late or forged, and that every
must-check result keeps its `#[\NoDiscard]`.

## License

GPL-2.0-or-later
