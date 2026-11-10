<?php declare(strict_types=1);
$routes = [
    '/' => 'home_controller',
    '/article' => 'article_controller',
    '/search' => 'search_controller',
];
$route = $_GET['route'] ?? '/';
$controller = $routes[$route] ?? 'home_controller';
$controller();
