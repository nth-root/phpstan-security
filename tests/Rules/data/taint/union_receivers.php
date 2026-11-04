<?php

declare(strict_types=1);

use Symfony\Component\HttpFoundation\Request;

class UnionReceiverRepository
{
    public function find(string $name): void
    {
        exec('grep ' . $name);
    }

    public function name(): string
    {
        return $_GET['name'];
    }
}

function cases(PDO|false $pdo, Request|array $request, UnionReceiverRepository|array $repository): void
{
    $pdo->query($_GET['sql']); // sink on PDO|false
    exec($request->get('cmd')); // source on Request|array
    $repository->find($_GET['name']); // argument into a method on UnionReceiverRepository|array
    exec($repository->name()); // return value of a method on UnionReceiverRepository|array
}
