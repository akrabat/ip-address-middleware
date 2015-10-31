# Client IP address middleware

PSR-7 Middleware that determines the client IP address and stores it as an `ServerRequest` attribute called `ip_address`.

[![Build status][Master image]][Master]

## Installation

`composer require akrabat/rka-ip-address-middleware`

## Usage

In Slim 3:

```php
$trustProxyHeaders = true; // Note: Never trust the IP address for security processes!
$app->add(new RKA\Middleware\IpAddress($trustProxyHeaders));

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
