<?php declare(strict_types=1);
function user_find(int $id): ?array
{
    $statement = db()->prepare('SELECT id, name, email FROM users WHERE id = ?');
    $statement->execute([$id]);
    $row = $statement->fetch(PDO::FETCH_ASSOC);
    return $row === false ? null : $row;
}
