<?php

declare(strict_types=1);

use Illuminate\Http\JsonResponse;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Http\Response;

function cases(Request $request): void
{
    new Response('<p>Hello ' . $request->input('name') . '</p>'); // unsafe
    new Response(content: $request->input('html')); // unsafe
    new RedirectResponse($request->input('next')); // unsafe (inherits Symfony's constructor)
}

function safe(Request $request): void
{
    new Response('Hello', $request->input('status')); // safe (only the content is a sink)
    new JsonResponse($request->input('data')); // safe (JSON, not HTML)
}
