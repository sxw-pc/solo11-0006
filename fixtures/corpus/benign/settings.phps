<?php declare(strict_types=1);
function setting(string $key, mixed $default = null): mixed
{
    static $values = null;
    if ($values === null) {
        $values = require __DIR__ . '/config.phps';
    }
    return array_key_exists($key, $values) ? $values[$key] : $default;
}
