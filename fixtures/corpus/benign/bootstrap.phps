<?php declare(strict_types=1);
define('APP_START', microtime(true));
$config = require __DIR__ . '/config.phps';
require_once __DIR__ . '/database.phps';
require_once __DIR__ . '/lib/validator.phps';
