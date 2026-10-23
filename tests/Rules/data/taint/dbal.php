<?php

declare(strict_types=1);

use Doctrine\DBAL\Connection;

function cases(Connection $connection): void
{
    $connection->executeQuery($_GET['sql']); // unsafe
    $connection->executeStatement($_GET['sql']); // unsafe
    $connection->prepare($_GET['sql']); // unsafe
    $connection->executeQuery(params: [], sql: $_GET['sql']); // unsafe
    $connection->fetchOne($_GET['sql']); // unsafe (the fetch* methods name the SQL $query)
}

function safe(Connection $connection): void
{
    $connection->executeQuery('SELECT * FROM users WHERE id = ?', $_GET['params']); // safe (parameters are bound)
    $connection->executeStatement('DELETE FROM users WHERE id = ?', [], $_GET['types']); // safe (types are not SQL)
    $connection->fetchOne('SELECT name FROM users WHERE id = ?', $_GET['params']); // safe (parameters are bound)
    $connection->quote($_GET['value']); // safe (not a sink)
}
