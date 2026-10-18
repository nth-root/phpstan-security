<?php

declare(strict_types=1);

function concat(): void
{
    exec('ls ' . $_GET['dir']); // unsafe
}

function withVariable(): void
{
    $dir = $_GET['dir'];
    exec('ls ' . $dir); // unsafe
}

function withVariable2(): void
{
    $command = 'ls ' . $_GET['dir'];
    exec($command); // unsafe
}

function safe(): void
{
    exec('ls ' . 'tmp'); // safe
}

function multiple(): void
{
    exec($_GET['a'] . $_POST['b']); // unsafe
}

function duplicate(): void
{
    exec($_GET['a'] . $_GET['b']); // unsafe but reports $_GET only once
}
