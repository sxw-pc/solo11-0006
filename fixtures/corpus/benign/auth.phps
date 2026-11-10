<?php declare(strict_types=1);
function auth_attempt(string $email, string $password): bool
{
    $user = user_find_by_email($email);
    if ($user === null) {
        return false;
    }
    return password_verify($password, $user['password_hash']);
}
