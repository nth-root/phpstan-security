<?php

declare(strict_types=1);

function cases(): void
{
    echo e($_GET['name']); // safe
    exec(e($_GET['cmd'])); // unsafe (escaped for HTML, not the shell)

    exec(data_get($_GET, 'cmd')); // unsafe
    exec(data_get(['cmd' => 'ls'], 'cmd', $_GET['cmd'])); // unsafe (default)
    exec(data_get(['cmd' => 'ls'], $_GET['key'])); // safe (only the key is user input)
}
