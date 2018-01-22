# vk-auth
tiny lib to get vk auth cookie (remixsid) using valid mobile phone number and password


# install via composer

```bash
composer require biganfa/vk-auth
```


# usage

```php

$agent = new \VkAuth\VkAuthAgent($vkCell, $vkPassword);
$remixsid = $agent->getRemixsid(); // makes few http requests to vk.com and returns valid remixsid value

// CookieJar object for usage in Guzzle Client, see [guzzle docs](http://docs.guzzlephp.org/en/latest/quickstart.html#cookies)
$jar = $agent->getAuthorizedCookieJar();

```


# example

there is an example.php command-line script. It will print friends list of the account.
 To run it, you need to create a file called _test_login_pass_constants.php_
which contains two required constants (valid vk mobile phone & password), e.g.

```php
<?php
const TEST_VK_LOGIN = '81234567890';
const TEST_VK_PATH = 'password';

```

run it
```bash
php example.php
```
