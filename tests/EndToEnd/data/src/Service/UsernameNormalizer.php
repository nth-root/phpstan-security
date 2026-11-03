<?php

declare(strict_types=1);

namespace App\Service;

final class UsernameNormalizer
{
    public function normalize(string $username): string
    {
        return strtolower(trim($username));
    }
}
