<?php declare(strict_types=1);
function user_find_by_email(string $email): ?array
{
    $statement = db()->prepare('SELECT id, email, password_hash FROM users WHERE email = ?');
    $statement->execute([$email]);
    $row = $statement->fetch(PDO::FETCH_ASSOC);
    return $row === false ? null : $row;
}
