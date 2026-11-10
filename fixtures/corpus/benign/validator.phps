<?php declare(strict_types=1);
function valid_email(string $value): bool
{
    return filter_var($value, FILTER_VALIDATE_EMAIL) !== false;
}
function valid_slug(string $value): bool
{
    return preg_match('/^[a-z0-9-]{1,80}$/', $value) === 1;
}
