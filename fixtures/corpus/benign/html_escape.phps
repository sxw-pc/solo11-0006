<?php declare(strict_types=1);
function h(string $value): string
{
    return htmlspecialchars($value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}
function safe_url(string $value): string
{
    return filter_var($value, FILTER_SANITIZE_URL) ?: '/';
}
