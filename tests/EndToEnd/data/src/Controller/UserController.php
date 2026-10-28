<?php

declare(strict_types=1);

namespace App\Controller;

use App\Repository\UserRepository;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Attribute\Route;

final readonly class UserController
{
    #[Route('/user/{username}')]
    public function show(string $username, UserRepository $repository): Response
    {
        $user = $repository->get($username);

        return new Response($username);
    }
}
