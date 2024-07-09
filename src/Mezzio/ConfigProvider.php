<?php

declare(strict_types=1);

namespace RKA\Middleware\Mezzio;

use RKA\Middleware\IpAddress;

class ConfigProvider
{
    public function __invoke(): array
    {
        return [
            'dependencies' => $this->getDependencies(),
        ];
    }

    private function getDependencies(): array
    {
        return [
          'factories' => [
              IpAddress::class => IpAddressFactory::class,
          ]
        ];
    }
}
