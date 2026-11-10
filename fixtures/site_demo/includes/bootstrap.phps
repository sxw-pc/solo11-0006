<?php declare(strict_types=1);
define('SITE_ROOT', dirname(__DIR__));
$config = require SITE_ROOT . '/config/app.phps';
require SITE_ROOT . '/lib/validator.phps';
require SITE_ROOT . '/lib/pagination.phps';
require SITE_ROOT . '/lib/router.phps';
require SITE_ROOT . '/models/Article.phps';
require SITE_ROOT . '/models/User.phps';
