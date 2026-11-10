<?php declare(strict_types=1);
require __DIR__ . '/includes/bootstrap.phps';
$pageTitle = 'Demo Publishing';
$articles = article_recent(6);
include __DIR__ . '/includes/header.phps';
echo '<main><h1>Latest articles</h1></main>';
include __DIR__ . '/includes/footer.phps';
