<?php
namespace RKA\Middleware;

use Psr\Http\Message\MessageInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;

class IpAddress implements MiddlewareInterface
{
    /**
     * Enable checking of proxy headers (X-Forwarded-For to determined client IP.
     *
     * Defaults to false as only $_SERVER['REMOTE_ADDR'] is a trustworthy source
     * of IP address.
     *
     * @var bool
     */
    protected $checkProxyHeaders;

    /**
     * List of trusted proxy IP addresses
     *
     * If not empty, then one of these IP addresses must be in $_SERVER['REMOTE_ADDR']
     * in order for the proxy headers to be looked at.
     *
     * @var array
     */
    protected $trustedProxies = [];

    /**
     * List of trusted proxy IP wildcard ranges
     *
     * @var array
     */
    protected $trustedWildcards;

    /**
     * List of trusted proxy IP CIDR ranges
     *
     * @var array
     */
    protected $trustedCidrs;

    /**
     * Name of the attribute added to the ServerRequest object
     *
     * @var string
     */
    protected $attributeName = 'ip_address';

    /**
     * Number of hops that can be considered safe. Set to a positive number to enable.
     *
     * @var int
     */
    protected $hopCount = 0;

    /**
     * List of proxy headers inspected for the client IP address
     *
     * @var array
     */
    protected $headersToInspect = [
        'Forwarded',
        'X-Forwarded-For',
        'X-Forwarded',
        'X-Cluster-Client-Ip',
        'Client-Ip',
    ];

    /**
     * Constructor
     *
     * @param bool $checkProxyHeaders Whether to use proxy headers to determine client IP
     * @param ?array $trustedProxies  Unordered list of IP addresses of trusted proxies
     * @param string $attributeName   Name of attribute added to ServerRequest object
     * @param array $headersToInspect List of headers to inspect
     * @param int $hopCount           Number of hops that can be considered safe. Set to a positive number to enable
     */
    public function __construct(
        $checkProxyHeaders = false,
        ?array $trustedProxies = null,
        $attributeName = null,
        array $headersToInspect = [],
        int $hopCount = 0
    ) {
        if ($checkProxyHeaders && $trustedProxies === null) {
            throw new \InvalidArgumentException('Use of the forward headers requires an array for trusted proxies.');
        }

        $this->checkProxyHeaders = $checkProxyHeaders;

        if (is_array($trustedProxies)) {
            foreach ($trustedProxies as $proxy) {
                if (strpos($proxy, '*') !== false) {
                    // Wildcard IP address
                    $this->trustedWildcards[] = $this->parseWildcard($proxy);
                } elseif (strpos($proxy, '/') > 6) {
                    // CIDR notation
                    $this->trustedCidrs[] = $this->parseCidr($proxy);
                } else {
                    // String-match IP address
                    $this->trustedProxies[] = $proxy;
                }
            }
        }

        if ($attributeName) {
            $this->attributeName = $attributeName;
        }

        if (!empty($headersToInspect)) {
            $this->headersToInspect = $headersToInspect;
        }

        $this->hopCount = $hopCount;
    }

    private function parseWildcard(string $ipAddress): array
    {
        // IPv4 has 4 parts separated by '.'
        // IPv6 has 8 parts separated by ':'
        if (strpos($ipAddress, '.') > 0) {
            $delim = '.';
            $parts = 4;
        } else {
            $delim = ':';
            $parts = 8;
        }

        return explode($delim, $ipAddress, $parts);
    }

    private function parseCidr(string $ipAddress): array
    {
        list($subnet, $bits) = explode('/', $ipAddress, 2);
        $subnet = ip2long($subnet);
        $mask = -1 << (32 - $bits);
        $min = $subnet & $mask;
        $max = $subnet | ~$mask;

        return [$min, $max];
    }

    /**
     * {@inheritDoc}
     *
     * Set the "$attributeName" attribute to the client's IP address as determined from
     * the proxy header (X-Forwarded-For or from $_SERVER['REMOTE_ADDR']
     */
    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        $ipAddress = $this->determineClientIpAddress($request);
        $request = $request->withAttribute($this->attributeName, $ipAddress);

        return $handler->handle($request);
    }

    /**
     * Set the "$attributeName" attribute to the client's IP address as determined from
     * the proxy header (X-Forwarded-For or from $_SERVER['REMOTE_ADDR']
     *
     * @param ServerRequestInterface $request PSR7 request
     * @param ResponseInterface $response     PSR7 response
     * @param callable $next                  Next middleware
     *
     * @return ResponseInterface
     */
    public function __invoke(ServerRequestInterface $request, ResponseInterface $response, $next)
    {
        if (!$next) {
            return $response;
        }

        $ipAddress = $this->determineClientIpAddress($request);
        $request = $request->withAttribute($this->attributeName, $ipAddress);

        return $next($request, $response);
    }

    /**
     * Find out the client's IP address from the headers available to us
     *
     * @param  ServerRequestInterface $request PSR-7 Request
     * @return string
     */
    protected function determineClientIpAddress($request): ?string
    {
        $ipAddress =  null;

        $serverParams = $request->getServerParams();
        if (isset($serverParams['REMOTE_ADDR'])) {
            $remoteAddr = $this->extractIpAddress($serverParams['REMOTE_ADDR']);
            if (filter_var($remoteAddr, FILTER_VALIDATE_IP)) {
                $ipAddress = $remoteAddr;
            }
        }
        if ($ipAddress === null) {
            // do not continue if there isn't a valid remote address
            return $ipAddress;
        }

        if (!$this->checkProxyHeaders) {
            // do not check if configured to not check
            return $ipAddress;
        }

        // If trustedProxies is empty, then the remote address is the trusted proxy
        $trustedProxies = $this->trustedProxies;
        if (empty($trustedProxies) && empty($this->trustedWildcards) && empty($this->trustedCidrs)) {
            $trustedProxies[] = $ipAddress;
        }

        // find the first non-empty header from the headersToInspect list and use just that one
        foreach ($this->headersToInspect as $header) {
            if ($request->hasHeader($header)) {
                $headerValue = $request->getHeaderLine($header);
                if (!empty($headerValue)) {
                    $ipAddress = $this->getIpAddressFromHeader(
                        $header,
                        $headerValue,
                        $ipAddress,
                        $trustedProxies,
                        $this->hopCount
                    );
                    break;
                }
            }
        }

        return empty($ipAddress) ? null : $ipAddress;
    }

    public function getIpAddressFromHeader(
        string $headerName,
        string $headerValue,
        string $thisIpAddress,
        array $trustedProxies,
        int $hopCount
    ) {
        if (strtolower($headerName) == 'forwarded') {
            // The Forwarded header is different, so we need to extract the for= values. Note that we perform a
            // simple extraction here, and do not support the full RFC 7239 specification.
            preg_match_all('/for=([^,;]+)/i', $headerValue, $matches);
            $ipList = $matches[1];

            // If any of the items in the list are not an IP address, then we ignore the entire list for now
            foreach ($ipList as $ip) {
                $ip = $this->extractIpAddress($ip);
                if (!filter_var($ip, FILTER_VALIDATE_IP)) {
                    return $thisIpAddress;
                }
            }
        } else {
            $ipList = explode(',', $headerValue);
        }
        $ipList[] = $thisIpAddress;

        // Remove port from each item in the list
        $ipList = array_map(function ($ip) {
            return $this->extractIpAddress(trim($ip));
        }, $ipList);

        // Ensure all IPs are valid and return $ipAddress if not
        foreach ($ipList as $ip) {
            if (!filter_var($ip, FILTER_VALIDATE_IP)) {
                return $thisIpAddress;
            }
        }

        // walk list from right to left removing known proxy IP addresses.
        $ipList = array_reverse($ipList);
        $count = 0;
        foreach ($ipList as $ip) {
            $count++;
            if (!$this->isTrustedProxy($ip, $trustedProxies)) {
                if ($count <= $hopCount) {
                    continue;
                }
                return $ip;
//            } else {
//                if ($count <= $hopCount) {
//                    continue;
//                }
            }
        }

        return $thisIpAddress;
    }

    protected function isTrustedProxy(string $ipAddress, array $trustedProxies): bool
    {
        if (in_array($ipAddress, $trustedProxies)) {
            return true;
        }

        // Do we match a wildcard?
        if ($this->trustedWildcards) {
            // IPv4 has 4 parts separated by '.'
            // IPv6 has 8 parts separated by ':'
            if (strpos($ipAddress, '.') > 0) {
                $delim = '.';
                $parts = 4;
            } else {
                $delim = ':';
                $parts = 8;
            }

            $ipAddrParts = explode($delim, $ipAddress, $parts);
            foreach ($this->trustedWildcards as $proxy) {
                if (count($proxy) !== $parts) {
                    continue; // IP version does not match
                }
                $match = true;
                foreach ($proxy as $i => $part) {
                    if ($part !== '*' && $part !== $ipAddrParts[$i]) {
                        $match = false;
                        break; // IP does not match, move to next proxy
                    }
                }
                if ($match) {
                    return true;
                }
            }
        }

        // Do we match a CIDR address?
        if ($this->trustedCidrs) {
            // Only IPv4 is supported for CIDR matching
            $ipAsLong = ip2long($ipAddress);
            if ($ipAsLong) {
                foreach ($this->trustedCidrs as $proxy) {
                    if ($proxy[0] <= $ipAsLong && $ipAsLong <= $proxy[1]) {
                        return true;
                    }
                }
            }
        }

        return false;
    }

    /**
     * Remove port from IPV4 address if it exists
     *
     * Note: leaves IPV6 addresses alone
     *
     * @param  string $ipAddress
     * @return string
     */
    protected function extractIpAddress($ipAddress)
    {
        $parts = explode(':', $ipAddress);
        if (count($parts) == 1) {
            return $ipAddress;
        }
        if (count($parts) == 2) {
            if (filter_var($parts[0], FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) !== false) {
                return $parts[0];
            }
        }

        // If the $ipAddress starts with a [ and ends with ] or ]:port, then it is an IPv6 address and
        // we can extract the IP address
        $ipAddress = trim($ipAddress, '"\'');
        if (substr($ipAddress, 0, 1) === '['
            && (substr($ipAddress, -1) === ']' || preg_match('/\]:\d+$/', $ipAddress))) {
            // Extract IPv6 address between brackets
            preg_match('/\[(.*?)\]/', $ipAddress, $matches);
            $ipAddress = $matches[1];
        }

        return $ipAddress;
    }
}
