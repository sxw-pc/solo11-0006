<?php declare(strict_types=1);
require __DIR__ . '/bootstrap.phps';
$pageTitle = 'Welcome';
$articles = article_recent(6);
include __DIR__ . '/views/home.phps';
