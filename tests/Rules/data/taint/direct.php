<?php

declare(strict_types=1);

function cases(): void
{
    $out = null;

    exec($_GET['cmd']); // unsafe
    exec('ls'); // safe
    strlen($_GET['cmd']); // safe (not a sink)
    exec('ls', $_GET['out']); // safe (only argument 0 is a sink)
    exec(output: $out, command: $_GET['cmd']); // unsafe
    exec(); // safe
    exec(command: 'ls', output: $_GET['x']); // safe
}
