<?php declare(strict_types=1);
function route_request(array $routes): void
{
    $path = parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH);
    $handler = $routes[$path ?? '/'] ?? 'home_controller';
    $handler();
}
