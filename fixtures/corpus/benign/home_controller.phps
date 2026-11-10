<?php declare(strict_types=1);
function home_controller(): void
{
    $articles = article_recent(6);
    render('home', ['articles' => $articles, 'pageTitle' => 'Home']);
}
