<?php
namespace RKA\Middleware;

use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Message\ResponseInterface;

class IpAddress
{
    /**
     * Enable checking of proxy headers (X-Forwarded-For to determined client IP.
     *
     * Defaults to false as only $_SERVER['REMOTE_ADDR'] is a trustworthy source
     * of IP address.
     *
     * @var bool
     */
    protected $useProxy;

    /**
     * @param bool $useProxy Whether to use proxy headers to determine client IP
     */
    public function __construct($useProxy = false)
    {
        $this->useProxy = $useProxy;
    }

    /**
     * Set the "ip_address" attribute to the client's IP address as determined from
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
        $ipAddress = null;

        $serverParams = $request->getServerParams();
        if (isset($serverParams['REMOTE_ADDR']) && $this->isValidIpAddress($serverParams['REMOTE_ADDR'])) {
            $ipAddress = $serverParams['REMOTE_ADDR'];
        }

        if ($this->useProxy) {
            $headers = ['X-Forwarded-For', 'X-Forwarded', 'X-Cluster-Client-Ip', 'Client-Ip'];
            foreach ($headers as $header) {
                if ($request->hasHeader($header)) {
                    $ip = trim(current(explode(',', $request->getHeaderLine($header))));
                    if ($this->isValidIpAddress($ip)) {
                        $ipAddress = $ip;
                        break;
                    }
                }
            }
        }

        $request = $request->withAttribute('ip_address', $ipAddress);
        return $response = $next($request, $response);
    }

    protected function isValidIpAddress($ip)
    {
        $flags = FILTER_FLAG_IPV4 | FILTER_FLAG_IPV6;
        if (filter_var($ip, FILTER_VALIDATE_IP, $flags) === false) {
            return false;
        }
        return true;
    }
}
