<?php

declare(strict_types=1);

function cases(): void
{
    exec(trim($_GET['cmd'])); // unsafe
    exec(trim(' ls ', $_GET['chars'])); // safe (stripped characters don't reach exec)
    exec(str_replace('a', 'b', $_GET['cmd'])); // unsafe
    exec(str_replace('a', $_GET['x'], 'ls a')); // unsafe
    exec(str_replace($_GET['x'], 'b', 'ls')); // safe
    exec(sprintf('ls %s', $_GET['dir'])); // unsafe
    exec(implode(' ', $_GET['args'])); // unsafe
    exec(strtolower(trim($_GET['cmd']))); // unsafe (nested)
    exec(escapeshellarg($_GET['dir'])); // safe (escaped for the shell)

    $cmd = trim($_GET['cmd']);
    exec($cmd); // unsafe
}
