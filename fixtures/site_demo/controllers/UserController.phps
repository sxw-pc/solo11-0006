<?php declare(strict_types=1);
function login_controller(): void
{
    $email = trim((string) ($_POST['email'] ?? ''));
    $user = user_find_by_email($email);
    if ($user === null) {
        http_response_code(401);
    }
}
