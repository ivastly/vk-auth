<?php
/**
 * Date: 14.08.16
 * Time: 15:58
 */

namespace VkAuth\exception;


class VkAuthException extends \Exception {

    private $cell;
    private $password;

    /**
     * @return mixed
     */
    public function getPassword()
    {
        return $this->password;
    }

    /**
     * @return mixed
     */
    public function getCell()
    {
        return $this->cell;
    }

    public function __construct($cell, $password, $message)
    {
        parent::__construct("[cell = $cell, password = $password] $message");
    }
}