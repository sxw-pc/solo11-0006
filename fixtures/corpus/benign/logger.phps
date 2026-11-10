<?php declare(strict_types=1);
function app_log(string $level, string $message): void
{
    $line = sprintf('[%s] %s %s', gmdate('c'), $level, $message) . PHP_EOL;
    file_put_contents(__DIR__ . '/../storage/app.log', $line, FILE_APPEND | LOCK_EX);
}
