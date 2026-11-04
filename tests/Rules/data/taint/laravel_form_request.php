<?php

declare(strict_types=1);

use Illuminate\Foundation\Http\FormRequest;

class StoreItemRequest extends FormRequest {}

function cases(StoreItemRequest $request): void
{
    exec($request->validated('cmd'));
    exec($request->validated()['cmd']);

    $data = $request->validated();
    exec($data['cmd']);

    exec($request->safe()['cmd']);
    exec(implode(' ', $request->safe(['cmd'])));

    exec($request->safe()->input('cmd'));
    exec($request->safe()->string('cmd'));
    exec(implode(' ', $request->safe()->all()));
    exec(implode(' ', $request->safe()->only(['cmd'])));
    exec(implode(' ', $request->safe()->except(['id'])));
    exec(implode(' ', $request->safe()->keys()));

    // inherited Request method
    exec($request->input('cmd'));
}

function safe(StoreItemRequest $request): void
{
    exec($request->safe()->integer('cmd'));
    exec($request->safe()->boolean('cmd'));
}
