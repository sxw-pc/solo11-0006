<?php declare(strict_types=1);
$error = '';
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $email = trim((string) ($_POST['email'] ?? ''));
    $password = (string) ($_POST['password'] ?? '');
    if (!auth_attempt($email, $password)) {
        $error = 'Invalid credentials';
    }
}
include __DIR__ . '/includes/header.phps';
echo $error === '' ? '<p>Sign in</p>' : '<p>' . h($error) . '</p>';
include __DIR__ . '/includes/footer.phps';
