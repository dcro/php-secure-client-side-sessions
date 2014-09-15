PHP Secure Client Side Session Handler
======================================

Securely store PHP session information on the client side using encrypted cookies (with [AES encryption](http://en.wikipedia.org/wiki/Advanced_Encryption_Standard)). This is useful in cases where you don't want to store the session information on a file system or database (e.g. usually when using load balancing or servers in different geographical regions).

Because there's a browser limit of around 4KB of data available for cookies, the session data is first compressed using the [deflate](http://en.wikipedia.org/wiki/DEFLATE) algorithm. You should also keep in mind that the session data stored in the client side cookie is sent back to the server with every request so it's important to keep the data as small as possible.

By default, the class is configured to only set the data cookie over a secure `HTTPS` connection. This behaviour can be overridden by changing the `secureCookie` static var to `false`.

You can also customize the cookie specific settings (name, domain, path, etc.) using the `cookieName`, `cookiePath`, `cookieDomain` and `cookieHTTPOnly` static vars or you can customize the data compression level (for the deflate algorithm) using the `compressionLevel` static var (supported values from 0 to 9).

To use the library in your code, simply include the <SecureClientSideSessionHandler.php> file and initialize the session handler with:

```php
SecureClientSideSessionHandler::initialize('<your-encryption-key>', '<your-encryption-key-salt>');
```

The encryption key and encryption key salt can be any string values (they don't need to be very long as the final encryption key is an `SHA256` hash on `the-encryption-key` + `random-salt` + `the-encryption-key-salt`).

If you want to enable the session data cookie over `HTTP` (disabled by default), you'll need to initialize the session handler with:

```php
SecureClientSideSessionHandler::$cookieSecure = false;
SecureClientSideSessionHandler::initialize('<your-encryption-key>', '<your-encryption-key-salt>');
```

The default cookie name for the session handler is `PHPSESSDATA`. You can customize the cookie name with:

```php
SecureClientSideSessionHandler::$cookieName = 'CUSTOM-COOKIE-NAME';
SecureClientSideSessionHandler::initialize('<your-encryption-key>', '<your-encryption-key-salt>');
```
