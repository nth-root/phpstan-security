<?php

declare(strict_types=1);

function viaVariable(): void
{
    $cmd = $_GET['cmd'];
    exec($cmd); // unsafe
}

function clean(): void
{
    $cmd = 'ls';
    exec($cmd); // safe
}

function chain(): void
{
    $a = $_POST['x'];
    $b = $a;
    system($b); // unsafe
}

function sameNameElsewhere(): void
{
    $cmd = 'ls'; // must not trigger on viaVariable()'s $cmd
    exec($cmd);
}

function cycle(): void
{
    $a = $b;
    $b = $a;
    exec($a); // cycle must not cause a crash
}
