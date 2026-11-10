<?php declare(strict_types=1);
function render(string $view, array $data = []): void
{
    $file = __DIR__ . '/../views/' . $view . '.phps';
    if (!is_file($file)) {
        http_response_code(404);
        return;
    }
    extract($data, EXTR_SKIP);
    include $file;
}
