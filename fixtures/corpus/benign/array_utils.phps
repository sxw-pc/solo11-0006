<?php declare(strict_types=1);
function pluck(array $rows, string $column): array
{
    $values = [];
    foreach ($rows as $row) {
        if (array_key_exists($column, $row)) {
            $values[] = $row[$column];
        }
    }
    return $values;
}
