<?php

declare(strict_types=1);

class SomeController
{
    public function __construct(private UnsafeRepository $repository) {}

    public function search(): void
    {
        $this->repository->search($_GET['q']);
    }
}
