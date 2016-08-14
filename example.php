<?php
/**
 * Date: 13.08.16
 * Time: 22:16
 * @Author http://github.com/biganfa
 */

require_once "vendor/autoload.php";

echo "vk auth lib test\n";


/** this file is in .gitignore, you need to create it manually. Example
 *
 *  const TEST_VK_LOGIN = '81234567890';
const TEST_VK_PATH = 'password';
 *
 * */
require_once "test_login_pass_constants.php";
$agent = new \VkAuth\VkAuthAgent(TEST_VK_LOGIN, TEST_VK_PATH, '/tmp/vk-auth.log', function ($message) {
    echo $message . PHP_EOL;
});

$jar = $agent->getAuthorizedCookieJar();


$client = new GuzzleHttp\Client([
    'base_uri' => 'http://vk.com',
    'timeout' => 10,
]);

/** @var \GuzzleHttp\Psr7\Response $response */
$response = $client->get(
    '/friends',
    [
        'allow_redirects' => true,
        'cookies' => $jar // auth cookie inside
    ]
);

$vkResponseBody = strval($response->getBody());

$friends = preg_match_all('/si_owner(.+)<\/a>/', $vkResponseBody, $matches);

echo "\n friends: \n";
echo implode("\n", $matches[1]);


echo "done\n";