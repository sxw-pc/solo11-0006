<?php declare(strict_types=1);
function pagination(int $total, int $page, int $perPage): array
{
    $pages = max(1, (int) ceil($total / max(1, $perPage)));
    $current = min(max(1, $page), $pages);
    return ['page' => $current, 'pages' => $pages, 'offset' => ($current - 1) * $perPage];
}
