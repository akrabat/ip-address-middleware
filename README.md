# Client IP address middleware

PSR-7 Middleware that determines the client IP address and stores it as an `ServerRequest` attribute called `ip_address`.

It checks the 'X-Forwarded-For', 'X-Forwarded', 'X-Cluster-Client-Ip', 'Client-Ip' headers for the first IP address it can find. If none of the headers exist, or do not have a valid IP address, then the `$_SERVER['REMOTE_ADDR']` is used.

*Note that the headers are only checked if the first parameter to the constructor is set to `true`.*

[![Build status][Master image]][Master]

## Installation

`composer require akrabat/rka-ip-address-middleware`

## Usage

In Slim 3:

```php
$lookAtProxyHeaders = true; // Note: Never trust the IP address for security processes!
$app->add(new RKA\Middleware\IpAddress($lookAtProxyHeaders));

$app->get('/', function ($request, $response, $args) {
    $ipAddress = $request->getAttribute('ip_address');

    return $response;
});
```

## Testing

* Code coverage: ``$ vendor/bin/phpcs``
* Unit tests: ``$ vendor/bin/phpunit``
* Code coverage: ``$ vendor/bin/phpunit --coverage-html ./build``


[Master]: https://travis-ci.org/akrabat/rka-content-type-renderer
[Master image]: https://secure.travis-ci.org/akrabat/rka-content-type-renderer.svg?branch=master
