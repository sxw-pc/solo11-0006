<?php declare(strict_types=1);
$pageTitle = 'Contact';
$sent = false;
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $sent = valid_email((string) ($_POST['email'] ?? ''));
}
include __DIR__ . '/includes/header.phps';
echo $sent ? '<p>Thanks.</p>' : '<p>Contact the editor.</p>';
include __DIR__ . '/includes/footer.phps';
