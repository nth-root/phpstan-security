<?php

declare(strict_types=1);

class UnsafeRepository
{
    public function __construct(private PDO $pdo) {}

    public function search(string $term): void
    {
        $this->pdo->query("SELECT * FROM users WHERE name LIKE '%$term%'"); // unsafe (called from ArgumentsController)
    }
}
