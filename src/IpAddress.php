<?php
namespace RKA\Middleware;

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
    protected $trustedWildcard;

    /**
     * List of trusted proxy IP CIDR ranges
     *
     * @var array
     */
    protected $trustedCidr;

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
                    // IPv6 is 8 parts separated by ':'
                    if (strpos($proxy, '.') > 0) {
                        $delim = '.';
                        $parts = 4;
                    } else {
                        $delim = ':';
                        $parts = 8;
                    }
                    $this->trustedWildcard[] = explode($delim, $proxy, $parts);
                } elseif (strpos($proxy, '/') > 6) {
                    // CIDR notation
                    list($subnet, $bits) = explode('/', $proxy, 2);
                    $subnet = ip2long($subnet);
                    $mask = -1 << (32 - $bits);
                    $min = $subnet & $mask;
                    $max = $subnet | ~$mask;
                    $this->trustedCidr[] = [$min, $max];
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

        return $response = $next($request, $response);
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

        $checkProxyHeaders = false;
        if ($this->checkProxyHeaders) {
            // Exact Match
            if ($this->trustedProxies && in_array($ipAddress, $this->trustedProxies)) {
                $checkProxyHeaders = true;
            }

            // Wildcard Match
            if ($this->checkProxyHeaders && $this->trustedWildcard) {
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
                foreach ($this->trustedWildcard as $proxy) {
                    if (count($proxy) !== $parts) {
                        continue; // IP version does not match
                    }
                    $match = true;
                    foreach ($proxy as $i => $part) {
                        if ($part !== '*' && $part !== $ipAddrParts[$i]) {
                            $match = false;
                            break;// IP does not match, move to next proxy
                        }
                    }
                    if ($match) {
                        $checkProxyHeaders = true;
                        break;
                    }
                }
            }

            // CIDR Match
            if ($this->checkProxyHeaders && $this->trustedCidr) {
                // Only IPv4 is supported for CIDR matching
                $ipAsLong = ip2long($ipAddress);
                if ($ipAsLong) {
                    foreach ($this->trustedCidr as $proxy) {
                        if ($proxy[0] <= $ipAsLong && $ipAsLong <= $proxy[1]) {
                            $checkProxyHeaders = true;
                            break;
                        }
                    }
                }
            }

            if (!$this->trustedProxies && !$this->trustedWildcard && !$this->trustedCidr) {
                $checkProxyHeaders = true;
            }

            if ($checkProxyHeaders) {
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
        }

        if (empty($ipAddress)) {
            $ipAddress = null;
        }

        return $ipAddress;
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
    protected function isValidIpAddress($ip)
    {
        $flags = FILTER_FLAG_IPV4 | FILTER_FLAG_IPV6;
        if (filter_var($ip, FILTER_VALIDATE_IP, $flags) === false) {
            return false;
        }
        return true;
    }

    /**
     * Find out the client's IP address from the headers available to us
     *
     * @param  ServerRequestInterface $request PSR-7 Request
     * @param  string $header Header name
     * @return string
     */
    private function getFirstIpAddressFromHeader($request, $header)
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
