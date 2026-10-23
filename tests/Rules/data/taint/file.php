<?php

declare(strict_types=1);

function cases(): void
{
    file_get_contents($_GET['url']); // unsafe (SSRF)
    file_get_contents(__DIR__ . '/pages/' . $_GET['page']); // unsafe (path traversal)
    copy('/tmp/upload', $_GET['target']); // unsafe (destination)
}

function safe(): void
{
    file_put_contents('/tmp/log', $_GET['message']); // safe (data is not a sink)
    fopen('/tmp/log', $_GET['mode']); // safe (mode is not a sink)
}
