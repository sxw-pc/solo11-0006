<?php declare(strict_types=1);
function search_controller(): void
{
    $query = trim((string) ($_GET['q'] ?? ''));
    $results = article_search($query, 20);
    render_view('search', ['query' => $query, 'results' => $results]);
}
