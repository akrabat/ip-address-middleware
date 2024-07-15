<?php

declare(strict_types=1);

namespace RKA\Middleware\Mezzio;

use Psr\Container\ContainerExceptionInterface;
use Psr\Container\ContainerInterface;
use Psr\Container\NotFoundExceptionInterface;
use RKA\Middleware\IpAddress;

class IpAddressFactory
{
    /**
     * @throws ContainerExceptionInterface
     * @throws NotFoundExceptionInterface
     */
    public function __invoke(ContainerInterface $container): IpAddress
    {
        $config = [];

        if ($container->has('config')) {
            $config = $container->get('config');
        }

        $checkProxyHeaders = $config['rka']['ip_address']['check_proxy_headers'] ?? false;
        $trustedProxies = $config['rka']['ip_address']['trusted_proxies'] ?? null;
        $attributeName = $config['rka']['ip_address']['attribute_name'] ?? null;
        $headersToInspect = $config['rka']['ip_address']['headers_to_inspect'] ?? [];

        return new IpAddress(
            $checkProxyHeaders,
            $trustedProxies,
            $attributeName,
            $headersToInspect
        );
    }
}
