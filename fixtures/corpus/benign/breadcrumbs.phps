<?php declare(strict_types=1);
function breadcrumbs(array $items): array
{
    $result = [];
    foreach ($items as $label => $target) {
        $result[] = ['label' => (string) $label, 'target' => (string) $target];
    }
    return $result;
}
