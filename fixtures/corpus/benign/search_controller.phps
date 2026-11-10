<?php declare(strict_types=1);
function search_controller(): void
{
    $query = trim((string) ($_GET['q'] ?? ''));
    $results = $query === '' ? [] : article_search($query, 20);
    render('search', ['query' => $query, 'results' => $results]);
}
