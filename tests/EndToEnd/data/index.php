<?php

declare(strict_types=1);

function run(): void
{
    $command = 'ls ' . $_GET['dir'];

    exec($command);
    exec('ls');

    echo $_GET['x'];
}
