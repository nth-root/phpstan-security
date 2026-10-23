<?php

declare(strict_types=1);

use Doctrine\DBAL\Connection;

function cases(Connection $connection): void
{
    $connection->executeQuery($_GET['sql']); // unsafe
    $connection->executeStatement($_GET['sql']); // unsafe
    $connection->prepare($_GET['sql']); // unsafe
    $connection->executeQuery(params: [], sql: $_GET['sql']); // unsafe
}

function fetchers(Connection $connection): void
{
    $connection->fetchAssociative($_GET['sql']); // unsafe
    $connection->fetchNumeric($_GET['sql']); // unsafe
    $connection->fetchOne($_GET['sql']); // unsafe
    $connection->fetchAllNumeric($_GET['sql']); // unsafe
    $connection->fetchAllAssociative($_GET['sql']); // unsafe
    $connection->fetchAllKeyValue($_GET['sql']); // unsafe
    $connection->fetchAllAssociativeIndexed($_GET['sql']); // unsafe
    $connection->fetchFirstColumn($_GET['sql']); // unsafe
    $connection->iterateNumeric($_GET['sql']); // unsafe
    $connection->iterateAssociative($_GET['sql']); // unsafe
    $connection->iterateKeyValue($_GET['sql']); // unsafe
    $connection->iterateAssociativeIndexed($_GET['sql']); // unsafe
    $connection->iterateColumn($_GET['sql']); // unsafe
}

function safe(Connection $connection): void
{
    $connection->executeQuery('SELECT * FROM users WHERE id = ?', $_GET['params']); // safe (parameters are bound)
    $connection->executeStatement('DELETE FROM users WHERE id = ?', [], $_GET['types']); // safe (types are not SQL)
    $connection->fetchOne('SELECT name FROM users WHERE id = ?', $_GET['params']); // safe (parameters are bound)
    $connection->quote($_GET['value']); // safe (not a sink)
}
