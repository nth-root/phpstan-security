<?php

declare(strict_types=1);

function procedural(mysqli $mysqli): void
{
    mysqli_query($mysqli, $_GET['sql']); // unsafe
    mysqli_query(query: $_GET['sql'], mysql: $mysqli); // unsafe (named arguments)
}

function objectOriented(mysqli $mysqli): void
{
    $mysqli->query($_GET['sql']); // unsafe
}

function safe(mysqli $mysqli): void
{
    mysqli_query($mysqli, 'SELECT 1', $_GET['mode']); // safe (only the query is a sink)
    mysqli_execute_query($mysqli, 'SELECT * FROM users WHERE id = ?', $_GET['params']); // safe (parameters are bound)
    $mysqli->execute_query('SELECT * FROM users WHERE id = ?', $_GET['params']); // safe (parameters are bound)
    $mysqli->real_escape_string($_GET['value']); // safe (not a sink)
}
