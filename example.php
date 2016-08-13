<?php
/**
 * Date: 13.08.16
 * Time: 22:16
 * @Author http://github.com/biganfa
 */

require_once "vendor/autoload.php";

echo "vk auth lib test\n";

$agent = new \VkAuth\VkAuthAgent();

$agent->test();


echo "done\n";