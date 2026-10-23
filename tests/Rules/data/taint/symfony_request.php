<?php

declare(strict_types=1);

use Symfony\Component\HttpFoundation\Request;

class RequestSubclass extends Request {}

class Lookalike
{
    public function get(string $key): string
    {
        return $key;
    }
}

function cases(Request $request, RequestSubclass $subclass): void
{
    exec($request->get('cmd')); // unsafe
    exec($request->getContent()); // unsafe
    exec($request->toArray()['cmd']); // unsafe

    $cmd = $request->get('cmd');
    exec($cmd); // unsafe

    exec($request->get('cmd') . $_GET['args']); // unsafe
    exec($subclass->get('cmd')); // unsafe
}

function safe(Lookalike $lookalike, mixed $unknown): void
{
    exec($lookalike->get('cmd')); // safe
    exec($unknown->get('cmd')); // safe
}
