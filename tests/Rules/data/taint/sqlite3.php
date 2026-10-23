<?php

declare(strict_types=1);

function cases(SQLite3 $sqlite): void
{
    $sqlite->query($_GET['sql']); // unsafe
}

function safe(SQLite3 $sqlite): void
{
    $sqlite->querySingle('SELECT name FROM users', $_GET['entireRow']); // safe (only the query is a sink)
    SQLite3::escapeString($_GET['value']); // safe (not a sink)
}
