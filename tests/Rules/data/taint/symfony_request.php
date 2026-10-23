<?php

declare(strict_types=1);

use Symfony\Component\HttpFoundation\ParameterBag;
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

function requestBagCases(Request $request): void
{
    exec($request->query->get('cmd')); // unsafe
    exec($request->headers->get('cmd')); // unsafe
    exec(implode(' ', $request->query->all())); // unsafe
    exec($request->getPayload()->get('cmd')); // unsafe
}

function safeRequestBag(Request $request): void
{
    exec('ls ' . $request->query->getInt('id')); // safe

    $bag = new ParameterBag(['cmd' => 'ls']);
    exec($bag->get('cmd')); // safe

    exec($request->attributes->get('cmd')); // not reported yet
    exec($request->server->get('cmd')); // not reported yet
}
