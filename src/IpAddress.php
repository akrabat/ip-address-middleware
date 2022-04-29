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
    protected $trustedProxies;

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
     * @param array $trustedProxies   List of IP addresses of trusted proxies
     * @param string $attributeName   Name of attribute added to ServerRequest object
     * @param array $headersToInspect List of headers to inspect
     */
    public function __construct(
        $checkProxyHeaders = false,
        array $trustedProxies = null,
        $attributeName = null,
        array $headersToInspect = []
    ) {
        if ($checkProxyHeaders && $trustedProxies === null) {
            throw new \InvalidArgumentException('Use of the forward headers requires an array for trusted proxies.');
        }

        $this->checkProxyHeaders = $checkProxyHeaders;

        if ($trustedProxies) {
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
    protected function determineClientIpAddress($request)
    {
        $ipAddress = '';

        $serverParams = $request->getServerParams();
        if (isset($serverParams['REMOTE_ADDR'])) {
            $remoteAddr = $this->extractIpAddress($serverParams['REMOTE_ADDR']);
            if ($this->isValidIpAddress($remoteAddr)) {
                $ipAddress = $remoteAddr;
            }
        }

        if ($this->shouldCheckProxyHeaders($ipAddress)) {
            foreach ($this->headersToInspect as $header) {
                if ($request->hasHeader($header)) {
                    $ip = $this->getFirstIpAddressFromHeader($request, $header);
                    if ($this->isValidIpAddress($ip)) {
                        $ipAddress = $ip;
                        break;
                    }
                }
            }
        }

        return empty($ipAddress) ? null : $ipAddress;
    }

    /**
     * Determine whether we should check proxy headers for specified ip address
     */
    protected function shouldCheckProxyHeaders(string $ipAddress): bool
    {
        //do not check if configured to not check
        if (!$this->checkProxyHeaders) {
            return false;
        }

        //if configured to check but no constraints
        if (!$this->trustedProxies && !$this->trustedWildcards && !$this->trustedCidrs) {
            return true;
        }

        // Exact Match for trusted proxies
        if ($this->trustedProxies && in_array($ipAddress, $this->trustedProxies)) {
            return true;
        }

        // Wildcard Match
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

        // CIDR Match
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

        //default - not check
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
        if (count($parts) == 2) {
            if (filter_var($parts[0], FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) !== false) {
                return $parts[0];
            }
        }

        return $ipAddress;
    }

    /**
     * Check that a given string is a valid IP address
     *
     * @param  string  $ip
     * @return boolean
     */
    protected function isValidIpAddress(string $ip): bool
    {
        return filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 | FILTER_FLAG_IPV6) !== false;
    }

    /**
     * Find out the client's IP address from the headers available to us
     *
     * @param  ServerRequestInterface $request PSR-7 Request
     * @param  string $header Header name
     * @return string
     */
    private function getFirstIpAddressFromHeader(MessageInterface $request, string $header): string
    {
        $items = explode(',', $request->getHeaderLine($header));
        $headerValue = trim(reset($items));

        if (ucfirst($header) == 'Forwarded') {
            foreach (explode(';', $headerValue) as $headerPart) {
                if (strtolower(substr($headerPart, 0, 4)) == 'for=') {
                    $for = explode(']', $headerPart);
                    $headerValue = trim(substr(reset($for), 4), " \t\n\r\0\x0B" . "\"[]");
                    break;
                }
            }
        }

        return $this->extractIpAddress($headerValue);
    }
}
