<?php declare(strict_types=1);
function notify_editor(string $subject, string $body): bool
{
    $to = 'editor@example.invalid';
    $headers = 'From: noreply@example.invalid';
    return mail($to, $subject, $body, $headers);
}
