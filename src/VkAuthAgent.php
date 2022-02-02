<?php
/**
 * Date: 14.08.16
 * Time: 0:12
 */


namespace VkAuth;


use GuzzleHttp\Client;
use GuzzleHttp\Cookie\CookieJar;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\UriInterface;
use VkAuth\exception\VkAuthException;

class VkAuthAgent
{

    private $remixsid;
    private $cell;
    private $password;
    private $logFilePath;
    private $verboseCallback;
    private $cookieJar;

    /**
     * @param $cell string vk cell phone number
     * @param $password string vk password as plain text
     * @param null $responsesDumpFilePath optional path to responses log file, e.g. /tmp/vk_auth.log
     * @param callable $verboseCallback optional callback accepting one string parameter to log general messages from the library
     */
    public function __construct($cell, $password, $responsesDumpFilePath = null, Callable $verboseCallback = null)
    {

        $this->cell = $cell;
        $this->password = $password;
        $this->logFilePath = $responsesDumpFilePath;
        $this->verboseCallback = $verboseCallback;

        if ($this->logFilePath) {

            // all network requests will be dumped to file
            file_put_contents($this->logFilePath, "vk auth agent dump " . date(DATE_RFC2822) . PHP_EOL, FILE_APPEND);
        }

        $this->cookieJar = new CookieJar();

    }

    private function isLoggingOn()
    {
        return !is_null($this->logFilePath);
    }

    private function verbose($message)
    {

        if ($this->verboseCallback) {
            call_user_func($this->verboseCallback, $message);
        }
    }

    private function retrieveRemixsid($cell, $password)
    {

        $redirectInfo = []; // url => [redirects]
        $createRedirectsLogLambda = function ($initialUrl) use (&$redirectInfo) {

            $redirectsLogLambda = function (
                RequestInterface $request,
                ResponseInterface $response,
                UriInterface $uri
            ) use (&$redirectInfo, $initialUrl) {

                $redirectInfo[$initialUrl] [] = strval($uri);
            };

            return $redirectsLogLambda;

        };

        $cell = trim($cell);
        $password = trim($password);


        $ua = 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.77 Safari/537.36';

        $jar = $this->cookieJar;
        $httpVkComClient = new Client([
            'base_uri' => 'http://vk.com/',
            'timeout' => 0,
            'allow_redirects' => [
                'on_redirect' => $createRedirectsLogLambda('http://vk.com/'),
            ],
            'headers' => [
                'User-Agent' => $ua,
            ]
        ]);

        /** @var \GuzzleHttp\Psr7\Response $response */
        $response = $httpVkComClient->get(
            '/',
            [
                'cookies' => $jar
            ]
        );

        $this->dumpGuzzleResponseBody('get vk.com/', $response, $jar);


        $body = $response->getBody();

        preg_match('/name="ip_h" value="(.+)"/', $body, $matches);
        $ip_h = $matches[1];
        preg_match('/name="lg_domain_h" value="(.+)"/', $body, $matches);
        $lg_domain_h = $matches[1];

        $this->verbose("ip_h and lg_domain_h params parsed: $ip_h | $lg_domain_h");

        if (!$ip_h || !$lg_domain_h) {
            throw new VkAuthException($cell, $password, "bad vk html, ip_h & lg_domain_h fields not found $body");
        }

        $httpsLoginVkComClient = new Client([
            'base_uri' => 'https://login.vk.com/',
            'timeout' => 0,
            'allow_redirects' => [
                'on_redirect' => $createRedirectsLogLambda('https://login.vk.com/'),
            ],
            'cookies' => true,
            'headers' => [
                'User-Agent' => $ua,
                'accept' => 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
                'content-type' => 'application/x-www-form-urlencoded',
                'origin' => 'http://vk.com',
                'referer' => 'http://vk.com/',
            ]
        ]);


        $response = $httpsLoginVkComClient->post(
            '/',
            [
                'cookies' => $jar,
                'query' => [
                    'act' => 'login',
                ],
                'form_params' => [
                    'act' => 'login',
                    'role' => 'al_frame',
                    'expire' => '',
                    'captcha_sid' => '',
                    'captcha_key' => '',
                    '_origin' => 'http://vk.com',
                    'ip_h' => $ip_h,
                    'lg_domain_h' => $lg_domain_h,
                    'email' => $cell,
                    'pass' => $password,
                ]
            ]
        );

        $this->dumpGuzzleResponseBody('post login.vk.com', $response, $jar);

        $cookiesAfterLogin = array_column($jar->toArray(), 'Value', 'Name');

        if (isset($cookiesAfterLogin['remixsid'])) {

            $remixsid = $cookiesAfterLogin['remixsid'];

            $this->verbose("remixsid retrieved: $remixsid");

            if ($remixsid == 'DELETED') {
                throw new VkAuthException($cell, $password, 'vk deleted remixsid => login & pass are wrong');
            }

            // ping vk.com/friends. Redirect to login.php means that security check required
            $utmostRedirectUrl = '';
            $onRedirectLambda = function (
                RequestInterface $request,
                ResponseInterface $response,
                UriInterface $uri
            ) use (&$utmostRedirectUrl, &$redirectInfo) {
                $utmostRedirectUrl = strval($uri);
                $redirectInfo['http://vk.com/friends'] [] = strval($uri);
            };


            /*
        * var params = {code: ge('code').value, to: '', al_page: '3', hash: 'fa52980c05a587aec5'};
        *
        * this response contains 'hash' param required in security check request
        *  */
            $response = $httpVkComClient->get(
                '/friends',
                [
                    'cookies' => $jar,
                    'allow_redirects' => [
                        'on_redirect' => $onRedirectLambda,
                    ],
                ]
            );

            $this->dumpGuzzleResponseBody('get vk.com/friends', $response, $jar);

            if ($utmostRedirectUrl) { // request to /friends was redirected for some reason (possibly to login.php for security check)

                if (strpos($utmostRedirectUrl, 'login.php') !== false) {

                    // redirected to security check page => need to do additional request

                    // extract hash parameter from /friends response
                    $getFriendsResponseBody = $response->getBody();

                    preg_match('/code(.+)al_page(.+)hash: \'(.+)\'}/', $getFriendsResponseBody, $matches);

                    if (!isset($matches[3])) {
                        throw new VkAuthException($cell, $password, "cant parse vk.com/friends response to find hash parameter for security check");
                    }

                    $securityCheckPostRequestHash = $matches[3];

                    // prepare short cell code for security check
                    $shortCellCode = preg_replace('/[^0-9]/', '', $cell);
                    $shortCellCode = preg_replace('/^(7|8|380)/', '', $shortCellCode);
                    $shortCellCode = preg_replace('/[0-9]{2}$/', '', $shortCellCode);

                    $this->verbose(
                        "posting sec check with cell $cell [$shortCellCode] and hash $securityCheckPostRequestHash"
                    );

                    $response = $httpVkComClient->post(
                        '/login.php',
                        [
                            'cookies' => $jar,
                            'query' => [
                                'act' => 'security_check',
                            ],
                            'allow_redirects' => [
                                'on_redirect' => $createRedirectsLogLambda('http://vk.com/login.php'),
                            ],
                            'form_params' => [
                                'al' => 1,
                                'al_page' => 3,
                                'code' => $shortCellCode, // cell without (+7 or +380) and two digits from the right
                                'hash' => $securityCheckPostRequestHash,
                                'to' => '',
                            ],
                        ]
                    );

                    $this->dumpGuzzleResponseBody('post vk.com/login.php', $response, $jar);

                    $securityCheckPostResponseBody = $response->getBody();
                    $this->verbose(
                        "sec check body returned body: $securityCheckPostResponseBody, short cell = $shortCellCode"
                    );
                    /*
                     * response types:
                     *
                     <!--19358<!><!>0<!>6709<!>8<!>Неизвестная ошибка<!><!>43976254    in case of error
                     <!--19358<!><!>0<!>6709<!>0<!><!int>2<!>К сожалению, цифры указаны неверно. У Вас осталось <b>2</b> попытки. in case of wrong cell code
                     <!--19359<!><!>0<!>6709<!>4<!>/<!>1 in case of success
                    */

                    if ((strpos($securityCheckPostResponseBody, '<b>') !== false) && (strpos(
                            $securityCheckPostResponseBody,
                            '</b>'
                        ))
                    ) {

                        throw new VkAuthException($cell, $password, "security check returned 'wrong cell code' error ($securityCheckPostResponseBody)");
                    }

                    if (strlen($securityCheckPostResponseBody) > (mb_strlen(
                                '<!--19358<!><!>0<!>6709<!>8<!>Неизвестная ошибка<!><!>43976254'
                            ) - 10)
                    ) {

                        throw new VkAuthException($cell, $password, "security check response too long, possible error, ($securityCheckPostResponseBody)");
                    }

                    // response looks good
                    return $remixsid;

                } else {
                    if (strpos($utmostRedirectUrl, 'friends') !== false) {

                        // redirected to /friends finally => we are fully logged in
                        $this->verbose("/friends opened after redirect, remixsid ready");
                        return $remixsid;
                    } else {

                        throw new VkAuthException($cell, $password, "unknown vk redirect (login.php expected)");
                    }
                }

            } else {

                // remixsid ready!

                $this->verbose("sec check is not required!");
                return $remixsid;
            }

        } else {

            if (isset($cookiesAfterLogin['remixauthcheck'])) {

                // two-factor auth enabled => impossible to continue
                throw new VkAuthException($cell, $password, "fatal error: two-factor auth enabled");
            }

            throw new VkAuthException($cell, $password, "fatal error: remixsid not found in cookies");
        }

    }

    private function dumpGuzzleResponseBody($urlDescription, ResponseInterface $response, CookieJar $jar)
    {
        if ($this->isLoggingOn()) {

            $message = "\n\nurl = $urlDescription " . date(DATE_RFC2822) . "\n";
            $message .= $response->getStatusCode() . ' ' . $response->getBody() . "\ncookies:\n" . var_export(
                    $jar->toArray(),
                    true
                );

            file_put_contents($this->logFilePath, $message, FILE_APPEND);
        }
    }

    /**
     * @return string remixsid auth cookie
     */
    public function getRemixsid()
    {

        $this->authorizeIfNeeded();

        return $this->remixsid;
    }

    private function authorizeIfNeeded()
    {

        if (!$this->remixsid) {
            $this->remixsid = $this->retrieveRemixsid($this->cell, $this->password);
        }
    }

    /**
     * @return CookieJar with valid auth cookie inside
     */
    public function getAuthorizedCookieJar()
    {

        $this->authorizeIfNeeded();

        return $this->cookieJar;
    }
}
