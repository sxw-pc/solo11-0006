<?php declare(strict_types=1);
session_start();
$_SESSION = [];
session_regenerate_id(true);
header('Location: /');
exit;
