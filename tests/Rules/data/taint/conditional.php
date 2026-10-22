<?php

declare(strict_types=1);

function cases(bool $flag): void
{
    exec($_GET['cmd'] ?? 'ls'); // unsafe
    exec($flag ? $_GET['cmd'] : 'ls'); // unsafe
    exec($flag ? 'ls' : $_GET['cmd']); // unsafe
    exec($_GET['cmd'] ?: 'ls'); // unsafe
    exec($_GET['flag'] ? 'ls' : 'pwd'); // safe ($_GET['flag'] is never passed to exec)
    exec(isset($_GET['cmd']) ? $_GET['cmd'] : 'ls'); // unsafe
    exec($_GET['a'] ?? $_POST['b'] ?? 'ls'); // unsafe ($_GET and $_POST)
}

function throughVariable(): void
{
    $cmd = $_GET['cmd'] ?? 'ls';
    exec($cmd); // unsafe
}
