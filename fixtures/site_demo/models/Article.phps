<?php declare(strict_types=1);
function article_recent(int $limit): array
{
    $statement = db()->prepare('SELECT id, title FROM articles ORDER BY id DESC LIMIT ?');
    $statement->bindValue(1, $limit, PDO::PARAM_INT);
    $statement->execute();
    return $statement->fetchAll(PDO::FETCH_ASSOC);
}
