<?php declare(strict_types=1);
function article_controller(): void
{
    $id = (int) ($_GET['id'] ?? 0);
    $article = article_find($id);
    if ($article === null) {
        http_response_code(404);
        return;
    }
    render('article', ['article' => $article]);
}
