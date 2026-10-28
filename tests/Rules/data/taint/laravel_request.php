<?php

declare(strict_types=1);

use Illuminate\Http\Request;

class ExtendedRequest extends Request {}

function cases(Request $request, ExtendedRequest $extendedRequest): void
{
    exec($request->input('cmd'));
    exec($request->query('cmd'));
    exec($request->post('cmd'));
    exec($request->cookie('cmd'));
    exec($request->header('cmd'));
    exec($request->server('cmd'));
    exec($request->json('cmd'));
    exec($request->route('cmd'));
    exec($request->string('cmd'));

    exec(implode(' ', $request->all()));
    exec(implode(' ', $request->only(['cmd'])));
    exec(implode(' ', $request->except(['cmd'])));
    exec(implode(' ', $request->keys()));

    // inherited Symfony method
    exec($request->getContent());

    exec($extendedRequest->input('cmd'));

    exec($request->string('cmd')->toString()); // Not reported yet
}

function safe(Request $request): void
{
    exec($request->integer('cmd'));
    exec($request->boolean('cmd'));
    exec($request->float('cmd'));
    exec($request->date('cmd'));

    exec($request->has('cmd'));
    exec($request->filled('cmd'));
}

function urlCases(Request $request): void
{
    exec($request->segment(1));
    exec(implode('/', $request->segments()));
    exec($request->path());
    exec($request->decodedPath());
    exec($request->url());
    exec($request->fullUrl());
    exec($request->fullUrlWithQuery([]));
    exec($request->fullUrlWithoutQuery([]));
    exec($request->host());
    exec($request->httpHost());
    exec($request->schemeAndHttpHost());
    exec($request->root());
}

function headerAndSessionCases(Request $request): void
{
    exec($request->userAgent());
    exec($request->bearerToken());
    exec($request->old('cmd'));
}
