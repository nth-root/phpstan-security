<?php

declare(strict_types=1);

function concat(): void
{
    $cmd = 'ls ';
    $cmd .= $_GET['dir'];
    exec($cmd); // unsafe
}

function coalesce(): void
{
    $cmd = null;
    $cmd ??= $_GET['cmd'];
    exec($cmd); // unsafe
}

function arithmetic(): void
{
    $count = 1;
    $count += $_GET['n'];
    exec('head -n ' . $count); // safe (numbers are safe)
}

function html(): void
{
    $html = '';
    $html .= '<pre>Hello ' . $_GET['name'] . '</pre>';
    echo $html; // unsafe
}
