<?php

declare(strict_types=1);

namespace App\Repository;

use Doctrine\DBAL\Connection;

final class UserRepository
{
    public function __construct(private Connection $connection) {}

    public function get(string $username): array
    {
        $result = $this->connection->executeQuery('SELECT * FROM users WHERE username = ' . $username);

        return $result->fetchAssociative();
    }
}
