<?php

declare(strict_types=1);

use Illuminate\Database\Connection;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;

class Post extends Model {}

class ReportingConnection extends Connection
{
    public function report(): array
    {
        return parent::select($_GET['sql']); // unsafe
    }
}

class CommandRequest extends Request
{
    public function run(): void
    {
        exec(parent::input('cmd')); // unsafe
        exec(self::input('cmd')); // unsafe
    }
}

function unresolved(string $class, string $method): void
{
    Post::whereRaw($_GET['sql']); // Not reported yet (no whereRaw() on Model without Larastan)
    UnknownClass::select($_GET['sql']);
    $class::select($_GET['sql']);
    DB::$method($_GET['sql']);
    exec(UnknownClass::input('cmd'));
}
