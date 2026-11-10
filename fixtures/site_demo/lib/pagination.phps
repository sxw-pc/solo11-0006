<?php declare(strict_types=1);
function page_window(int $total, int $page, int $perPage): array
{
    $pages = max(1, (int) ceil($total / max(1, $perPage)));
    return ['page' => min(max(1, $page), $pages), 'pages' => $pages];
}
