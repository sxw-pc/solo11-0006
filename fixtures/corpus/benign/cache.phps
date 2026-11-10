<?php declare(strict_types=1);
function cache_get(string $key): ?string
{
    $path = __DIR__ . '/../storage/cache/' . hash('sha256', $key) . '.txt';
    if (!is_file($path)) {
        return null;
    }
    $value = file_get_contents($path);
    return $value === false ? null : $value;
}
