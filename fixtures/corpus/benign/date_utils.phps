<?php declare(strict_types=1);
function display_date(string $isoDate): string
{
    $timestamp = strtotime($isoDate);
    return $timestamp === false ? 'unknown' : gmdate('Y-m-d', $timestamp);
}
