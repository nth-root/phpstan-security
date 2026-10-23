<?php

declare(strict_types=1);

function cases(): void
{
    include $_GET['page']; // unsafe
    include_once $_GET['page']; // unsafe
    require $_GET['page']; // unsafe
    require_once $_GET['page']; // unsafe
    include __DIR__ . '/pages/' . $_GET['page']; // unsafe
    include($_GET['page']); // unsafe
}

function safe(): void
{
    include __DIR__ . '/open_redirect.php'; // safe
}
