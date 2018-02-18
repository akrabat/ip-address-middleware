# Client IP address middleware

PSR-15 Middleware that determines the client IP address and stores it as an `ServerRequest` attribute called `ip_address`. It optionally checks various common proxy headers and then falls back to `$_SERVER['REMOTE_ADDR']`.

[![Build status][Master image]][Master]


## Configuration

The constructor takes 4 parameters which can be used to configure this middleware.

**Check proxy headers**

Note that the proxy headers are only checked if the first parameter to the constructor is set to `true`. If set to false, then only `$_SERVER['REMOTE_ADDR']` is used.

**Trusted Proxies**

You can set a list of proxies that are trusted as the second constructor parameter. If this list is set, then the proxy headers will only be checked if the `REMOTE_ADDR` is in the trusted list.

**Attribute name**

By default, the name of the attribute is '`ip_address`'. This can be changed by the third constructor parameter.

**Headers to inspect**

By default, this middleware checks the 'Forwarded', 'X-Forwarded-For', 'X-Forwarded', 'X-Cluster-Client-Ip' and 'Client-Ip' headers. You can replace this list with your own using the fourth constructor parameter.

## Installation

`composer require akrabat/ip-address-middleware`

## Usage

In Slim 3:

```php
$checkProxyHeaders = true; // Note: Never trust the IP address for security processes!
$trustedProxies = ['10.0.0.1', '10.0.0.2']; // Note: Never trust the IP address for security processes!
$app->add(new RKA\Middleware\IpAddress($checkProxyHeaders, $trustedProxies));

$app->get('/', function ($request, $response, $args) {
    $ipAddress = $request->getAttribute('ip_address');

    return $response;
});
```

## Testing

* Code style: ``$ vendor/bin/phpcs``
* Unit tests: ``$ vendor/bin/phpunit``
* Code coverage: ``$ vendor/bin/phpunit --coverage-html ./build``


[Master]: https://travis-ci.org/akrabat/ip-address-middleware
[Master image]: https://secure.travis-ci.org/akrabat/ip-address-middleware.svg?branch=master
