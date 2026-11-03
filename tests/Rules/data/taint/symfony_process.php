<?php

declare(strict_types=1);

use Symfony\Component\Process\Process;

function cases(): void
{
    Process::fromShellCommandline('ls ' . $_GET['dir']); // unsafe
    Process::fromShellCommandline(command: "ls {$_GET['dir']}"); // unsafe
}

function safe(): void
{
    Process::fromShellCommandline('ls "$DIR"', null, ['DIR' => $_GET['dir']]); // safe (passed as an environment variable)
    new Process(['ls', $_GET['dir']]); // safe (an array command bypasses the shell)
}
