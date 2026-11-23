<?php

declare(strict_types=1);

foreach ($_GET['ids'] as $id) {
    exec('kill ' . $id); // unsafe
}

foreach ($_GET['ids'] as $key => $id) {
    exec('kill ' . $key); // unsafe
}

foreach (['TERM', 'KILL'] as $key => $signal) {
    exec("kill -$signal 1"); // safe
    exec("kill -$key 1"); // safe
}

function foreachVariadic(int ...$pids): void
{
    foreach ($pids as $name => $pid) {
        exec("kill $pid"); // safe
        exec("kill $name"); // unsafe (string keys from named arguments)
    }
}

function foreachVariadicCopy(int ...$pids): void
{
    $copy = $pids;

    foreach ($copy as $name => $pid) {
        exec("kill $name"); // unsafe
    }
}

foreachVariadic(...$_GET['pids']);
foreachVariadicCopy(...$_GET['pids']);
