<?php
declare(strict_types=1);

namespace Flowpack\Cors\Http\Middleware;

use GuzzleHttp\Psr7\Response;
use Neos\Flow\Annotations as Flow;
use Neos\Flow\Log\Utility\LogEnvironment;
use Neos\Utility\Arrays;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;
use Psr\Log\LoggerInterface;

/**
 * @Flow\Scope("singleton")
 */
class CorsMiddleware implements MiddlewareInterface
{

    /**
     * @Flow\InjectConfiguration(path="allowedOrigins")
     * @var string[]
     */
    protected $allowedOrigins;

    /**
     * @Flow\InjectConfiguration(path="allowedMethods")
     * @var string[]
     */
    protected $allowedMethods;

    /**
     * @Flow\InjectConfiguration(path="allowedHeaders")
     * @var string[]
     */
    protected $allowedHeaders;

    /**
     * @Flow\InjectConfiguration(path="exposedHeaders")
     * @var string[]
     */
    protected $exposedHeaders;

    /**
     * @Flow\InjectConfiguration(path="allowCredentials")
     * @var bool
     */
    protected $allowCredentials = false;

    /**
     * @Flow\InjectConfiguration(path="maxAge")
     * @var int
     */
    protected $maxAge = 0;

    /**
     * @Flow\InjectConfiguration(path="optionsPassthrough")
     * @var false
     */
    protected $optionsPassthrough = false;

    /**
     * @Flow\InjectConfiguration(path="debug")
     * @var false
     */
    protected $debug = false;

    /**
     * @Flow\Inject
     * @var LoggerInterface
     */
    protected $systemLogger;

    // Internal properties

    /**
     * @var bool
     */
    protected $allowedOriginsAll = false;

    /**
     * @var string[]
     */
    protected $allowedPlainOrigins = [];

    /**
     * @var string[]
     */
    protected $allowedWildcardOrigins = [];

    /**
     * @var bool
     */
    protected $allowedHeadersAll = false;

    public function initializeObject() {
        // TODO Move conversion to static compilation, does not need to happen during runtime
        $this->allowedWildcardOrigins = [];
        foreach ($this->allowedOrigins as $origin) {
            // Normalize
            $origin = \strtolower($origin);
            if ($origin === '*') {
                $this->allowedOriginsAll = true;
                break;
            }

            if (($i = \strpos($origin, '*')) !== false) {
                $this->allowedWildcardOrigins[] = [\substr($origin, 0, $i), \substr($origin, $i+1)];
            } else {
                $this->allowedPlainOrigins[] = $origin;
            }
        }

        $this->allowedHeadersAll = false;
        // Origin is always appended as some browsers will always request for this header at preflight
        if (!\in_array('Origin', $this->allowedHeaders, true)) {
            $this->allowedHeaders[] = 'Origin';
        }

        foreach ($this->allowedHeaders as $headerKey) {
            if ($headerKey === '*') {
                $this->allowedHeadersAll = true;
                break;
            }
        }

        $this->exposedHeaders = \array_map('strtolower', $this->exposedHeaders);
        $this->allowedHeaders = \array_map('strtolower', $this->allowedHeaders);
        $this->allowedMethods = \array_map('strtoupper', $this->allowedMethods);


        if ($this->debug) {
            $this->systemLogger->debug('CORS Component: Init', LogEnvironment::fromMethodName(__METHOD__) + [
                    'allowedHeaders' => $this->allowedHeaders
                ]);
        }
    }

    public function process(ServerRequestInterface $request, RequestHandlerInterface $next): ResponseInterface
    {
        if ($request->getMethod() === 'OPTIONS') {
            if ($this->debug) {
                $this->systemLogger->debug(
                    'CORS Component: Preflight request',
                    LogEnvironment::fromMethodName(__METHOD__)
                );
            }
            return $this->handlePreflight($request, $next);
        } else {
            if ($this->debug) {
                $this->systemLogger->debug(
                    'CORS Component: Actual request',
                    LogEnvironment::fromMethodName(__METHOD__)
                );
            }
            return $this->handleActualRequest($request, $next);
        }
    }

    /**
     * Build a base HTTP Response in case of a missing authentication exception
     *
     * @return ResponseInterface
     */
    protected function buildHttpResponse(
        ServerRequestInterface $request,
        RequestHandlerInterface $next,
        int $noPassthroughResponseCode
    ): ResponseInterface
    {
        if ($this->optionsPassthrough) {
            $response = $next->handle($request);
        }
        else{
            $response = new Response($noPassthroughResponseCode);
        }

        return $response;
    }

    protected function handlePreflight(
        ServerRequestInterface $request,
        RequestHandlerInterface $next
    ): ResponseInterface
    {
        $origin = (string)\current($request->getHeader('Origin'));

        // Always set Vary headers
        // see https://github.com/rs/cors/issues/10,
        //     https://github.com/rs/cors/commit/dbdca4d95feaa7511a46e6f1efb3b3aa505bc43f#commitcomment-12352001
        $request->setHeader('Vary', ['Origin', 'Access-Control-Request-Method', 'Access-Control-Request-Headers']);

        if ($origin === '') {
            if ($this->debug) {
                $this->systemLogger->debug(
                    '    Preflight aborted: empty Origin header',
                    LogEnvironment::fromMethodName(__METHOD__)
                );
            }

            return $this->buildHttpResponse($request, $next,401);
        }

        if (!$this->isOriginAllowed($origin)) {
            if ($this->debug) {
                $this->systemLogger->debug(
                    sprintf('    Preflight aborted: origin "%s" not allowed', $origin),
                    LogEnvironment::fromMethodName(__METHOD__)
                );
            }
            return $this->buildHttpResponse($request, $next,401);
        }

        $requestMethod = $request->getHeader('Access-Control-Request-Method')[0];
        if (!$this->isMethodAllowed($requestMethod)) {
            if ($this->debug) {
                $this->systemLogger->debug(
                    sprintf('    Preflight aborted: method "%s" not allowed', $origin),
                    LogEnvironment::fromMethodName(__METHOD__)
                );
            }
            return $this->buildHttpResponse($request, $next,401);
        }

        $headerList = $request->getHeader("Access-Control-Request-Headers")[0];
        $requestHeaders = $this->parseHeaderList($headerList);
        if (!$this->areHeadersAllowed($requestHeaders)) {
            if ($this->debug) {
                $this->systemLogger->debug(
                    sprintf('    Preflight aborted: headers "%s" not allowed', $headerList),
                    LogEnvironment::fromMethodName(__METHOD__)
                );
            }
            return $this->buildHttpResponse($request, $next,401);
        }

        $response = $this->buildHttpResponse($request, $next,200);

        if ($this->allowedOriginsAll && !$this->allowCredentials) {
            $response = $response->withHeader('Access-Control-Allow-Origin', '*');
        } else {
            $response = $response->withHeader('Access-Control-Allow-Origin', $origin);
        }

        // Spec says: Since the list of methods can be unbounded, simply returning the method indicated
        // by Access-Control-Request-Method (if supported) can be enough
        $response = $response->withHeader('Access-Control-Allow-Methods', \strtoupper($requestMethod));

        if ($requestHeaders !== []) {
            // Spec says: Since the list of headers can be unbounded, simply returning supported headers
            // from Access-Control-Request-Headers can be enough
            $response = $response->withHeader('Access-Control-Allow-Headers', \implode(', ', $requestHeaders));
        }

        if ($this->allowCredentials) {
            $response = $response->withHeader('Access-Control-Allow-Credentials', 'true');
        }

        if ($this->maxAge > 0) {
            $response = $response->withHeader('Access-Control-Max-Age', $this->maxAge);
        }

        if ($this->debug) {
            $this->systemLogger->debug('    Preflight response headers', LogEnvironment::fromMethodName(__METHOD__) + [
                    'headers' => $response->getHeaders()
                ]);
        }

        return $response;
    }

    protected function handleActualRequest(
        ServerRequestInterface $request,
        RequestHandlerInterface $next
    ): ResponseInterface
    {
        $method = $request->getMethod();
        if ($method === 'OPTIONS') {
            if ($this->debug) {
                $this->systemLogger->debug(
                    '    Actual request no headers added: method == OPTIONS',
                    LogEnvironment::fromMethodName(__METHOD__)
                );
            }
            return $next->handle($request);
        }

        $origin = (string)\current($request->getHeader('Origin'));
        if ($origin === '') {
            if ($this->debug) {
                $this->systemLogger->debug(
                    '    Actual request no headers added: missing origin',
                    LogEnvironment::fromMethodName(__METHOD__)
                );
            }

            return $next->handle($request);
        }

        if (!$this->isOriginAllowed($origin)) {
            if ($this->debug) {
                $this->systemLogger->debug(
                    sprintf('    Actual request no headers added: origin "%s" not allowed', $origin),
                    LogEnvironment::fromMethodName(__METHOD__)
                );
            }

            return $next->handle($request);
        }

        // Note that spec does define a way to specifically disallow a simple method like GET or
        // POST. Access-Control-Allow-Methods is only used for pre-flight requests and the
        // spec doesn't instruct to check the allowed methods for simple cross-origin requests.
        // We think it's a nice feature to be able to have control on those methods though.
        if (!$this->isMethodAllowed($method)) {
            if ($this->debug) {
                $this->systemLogger->debug(
                    sprintf('    Actual request no headers added: method "%s" not allowed', $method),
                    LogEnvironment::fromMethodName(__METHOD__)
                );
            }
            return $next->handle($request);
        }

        $response = $next->handle($request)->withHeader('Vary', 'Origin', false);

        if ($this->allowedOriginsAll && !$this->allowCredentials) {
            $response = $response->withHeader('Access-Control-Allow-Origin', '*');
        } else {
            $response = $response->withHeader('Access-Control-Allow-Origin', $origin);
        }

        if ($this->exposedHeaders !== []) {
            $response = $response->setHeader('Access-Control-Expose-Headers', implode(', ', $this->exposedHeaders));
        }

        if ($this->allowCredentials) {
            $response = $response->setHeader('Access-Control-Allow-Credentials', 'true');
        }

        if ($this->debug) {
            $this->systemLogger->debug(
                '    Actual response added headers',
                LogEnvironment::fromMethodName(__METHOD__) + [
                    'headers' => $response->getHeaders()->getAll()
                ]
            );
        }

        return $response;
    }

    /**
     * @param string $origin
     * @return bool
     */
    protected function isOriginAllowed(string $origin) : bool
    {
        if ($this->allowedOriginsAll) {
            return true;
        }
        $origin = strtolower($origin);
        foreach ($this->allowedPlainOrigins as $o) {
            if ($origin === $o) {
                return true;
            }
        }
        foreach ($this->allowedWildcardOrigins as $w) {
            // TODO Test!!!
            $matches = strlen($origin) >= strlen($w[0]) + strlen($w[1]) && strpos($origin, $w[0]) === 0 && strpos($origin, $w[1]) === strlen($origin) - strlen($w[1]);
            if ($matches) {
                return true;
            }
        }
        return false;
    }

    /**
     * @param string $method
     * @return bool
     */
    protected function isMethodAllowed(string $method) : bool
    {
        if ($this->allowedMethods === []) {
            // If no method allowed, always return false, even for preflight request
            return false;
        }
        $method = \strtoupper($method);
        if ($method === 'OPTIONS') {
            // Always allow preflight requests
            return true;
        }
        foreach ($this->allowedMethods as $m) {
            if ($method === $m) {
                return true;
            }
        }
        return false;
    }

    /**
     * Tokenize + normalize a string containing a list of headers
     *
     * @param string $headerList
     * @return string[]
     */
    protected function parseHeaderList(string $headerList) : array
    {
        $headerList = strtolower($headerList);
        return Arrays::trimExplode(',', $headerList, true);
    }

    /**
     * @param string[] $headers
     * @return bool
     */
    protected function areHeadersAllowed(array $headers) : bool
    {
        if ($this->allowedHeadersAll || $this->allowedHeaders === []) {
            return true;
        }
        foreach ($headers as $header) {
            if (!in_array($header, $this->allowedHeaders, true)) {
                return false;
            }
        }
        return true;
    }
}
