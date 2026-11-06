<?php

declare(strict_types=1);

use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Request;

function cases(): void
{
    DB::select($_GET['sql']); // unsafe
    DB::raw($_GET['sql']); // unsafe
    DB::select(bindings: [], query: $_GET['sql']); // unsafe
    DB::select(Request::input('sql')); // unsafe
    DB::select(DB::raw($_GET['sql'])); // unsafe (reported on raw())
    DB::selectOne($_GET['sql']); // unsafe (camel-cased @method tag)
    DB::affectingStatement($_GET['sql']); // unsafe (camel-cased @method tag)
}

function safe(): void
{
    DB::select('SELECT * FROM users WHERE id = ?', [$_GET['id']]); // safe (bindings)
    exec(Request::integer('cmd')); // safe (not a source)
}
