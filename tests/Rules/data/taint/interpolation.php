<?php

declare(strict_types=1);

function interpolation(): void
{
    $dir = $_GET['dir'];
    exec("ls $dir"); // unsafe
    exec("ls {$_GET['dir']}"); // unsafe
}

function heredoc(): void
{
    $dir = $_GET['dir'];

    exec(<<<EOT
        ls $dir
        EOT); // unsafe
}

function safe(): void
{
    $dir = 'tmp';
    exec("ls $dir"); // safe
}
