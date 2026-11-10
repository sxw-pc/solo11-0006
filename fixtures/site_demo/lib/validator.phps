<?php declare(strict_types=1);
function valid_email(string $value): bool
{
    return filter_var($value, FILTER_VALIDATE_EMAIL) !== false;
}
function positive_int(mixed $value): int
{
    $number = filter_var($value, FILTER_VALIDATE_INT);
    return $number !== false && $number > 0 ? $number : 0;
}
