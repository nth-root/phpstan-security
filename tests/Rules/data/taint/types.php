<?php

declare(strict_types=1);

use Symfony\Component\Routing\Attribute\Route;

function casts(): void
{
    exec('kill ' . (int) $_GET['pid']); // safe
    exec('kill ' . intval($_GET['pid'])); // safe
    exec('sleep ' . count($_GET['items'])); // safe
}

function typedParameter(int $pid): void
{
    exec("kill $pid"); // safe (an int can't carry an injection)
}

function typedVariadicParameter(int ...$pids): void
{
    exec('kill ' . implode(' ', $pids)); // safe (an array of ints)
}

/**
 * @param int $pid
 */
function phpDocTypedParameter($pid): void
{
    exec("kill $pid"); // unsafe (PHPDoc types aren't trusted)
}

function arguments(): void
{
    typedParameter($_GET['pid']);
    typedVariadicParameter(...$_GET['pids']);
    phpDocTypedParameter($_GET['pid']);
}

class TypedRouteController
{
    #[Route('/processes/{pid}')]
    public function kill(int $pid): void
    {
        exec("kill $pid"); // safe
    }
}

function narrowing(): void
{
    $signal = $_GET['signal'];

    if (in_array($signal, ['TERM', 'KILL'], true)) {
        exec("kill -$signal 1"); // safe (narrowed to constant strings)
    }

    if (is_numeric($_GET['pid'])) {
        exec('kill ' . $_GET['pid']); // safe (narrowed to a numeric string)
    }

    exec('kill ' . $_GET['pid']); // unsafe
}
