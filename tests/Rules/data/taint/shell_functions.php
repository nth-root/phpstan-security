<?php

declare(strict_types=1);

function cases(): void
{
    popen($_GET['cmd'], 'r'); // unsafe
    proc_open($_GET['cmd'], [], $pipes); // unsafe
    pcntl_exec($_GET['cmd']); // unsafe
    pcntl_exec(args: [], path: $_GET['cmd']); // unsafe
    mail('admin@example.com', 'Report', 'Body', [], '-f' . $_GET['from']); // unsafe (passed to sendmail)
}

function safe(): void
{
    popen('ls', $_GET['mode']); // safe (only argument 0 is a sink)
    proc_open(['ls', $_GET['dir']], [], $pipes); // safe (array command bypasses the shell)
    pcntl_exec('/bin/ls', [$_GET['arg']]); // safe (args are not passed through a shell)
    mail($_GET['to'], 'Report', 'Body'); // safe (only additional_params reaches sendmail's command line)
}
