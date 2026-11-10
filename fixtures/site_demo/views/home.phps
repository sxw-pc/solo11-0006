<?php declare(strict_types=1); ?>
<main>
  <h1>Latest articles</h1>
  <ul>
  <?php foreach ($articles as $article): ?>
    <li><?= h($article['title']) ?></li>
  <?php endforeach; ?>
  </ul>
</main>
