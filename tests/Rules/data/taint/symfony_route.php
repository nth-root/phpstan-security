<?php

declare(strict_types=1);

use Symfony\Component\Routing\Annotation\Route as AnnotationRoute;
use Symfony\Component\Routing\Attribute\Route;

#[Route('/{locale}')]
class RouteController
{
    #[Route('/posts/{slug}')]
    public function show(string $slug, string $locale): void
    {
        exec($slug); // unsafe
        exec($locale); // unsafe
    }

    #[Route(path: '/posts/{id<\d+>?1}/{!page}')]
    public function requirements(string $id, string $page): void
    {
        exec($id); // unsafe
        exec($page); // unsafe
    }

    #[Route(path: ['en' => '/about/{topic}', 'nl' => '/over/{onderwerp}'])]
    public function localized(string $topic, string $onderwerp): void
    {
        exec($topic); // unsafe
        exec($onderwerp); // unsafe
    }

    #[AnnotationRoute('/legacy/{name}')]
    public function legacy(string $name): void
    {
        exec($name); // unsafe
    }

    #[Route('/search')]
    public function notInPath(string $query): void
    {
        exec($query); // safe
    }

    public function noRoute(string $slug, string $locale): void
    {
        exec($slug); // safe
        exec($locale); // safe
    }
}
