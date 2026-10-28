<?php

declare(strict_types=1);

use Illuminate\Database\Connection;
use Illuminate\Database\ConnectionInterface;
use Illuminate\Database\Eloquent\Builder as EloquentBuilder;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Query\Builder;

class Event extends Model {}

function connectionCases(ConnectionInterface $connection, Connection $concrete): void
{
    $connection->select($_GET['sql']); // unsafe
    $connection->selectOne($_GET['sql']); // unsafe
    $connection->cursor($_GET['sql']); // unsafe
    $connection->insert($_GET['sql']); // unsafe
    $connection->update($_GET['sql']); // unsafe
    $connection->delete($_GET['sql']); // unsafe
    $connection->statement($_GET['sql']); // unsafe
    $connection->affectingStatement($_GET['sql']); // unsafe
    $connection->unprepared($_GET['sql']); // unsafe
    $connection->raw($_GET['sql']); // unsafe
    $connection->select(bindings: [], query: $_GET['sql']); // unsafe
    $concrete->select($_GET['sql']); // unsafe
}

function queryBuilderCases(Builder $query): void
{
    $query->whereRaw($_GET['sql']); // unsafe
    $query->orWhereRaw($_GET['sql']); // unsafe
    $query->havingRaw($_GET['sql']); // unsafe
    $query->orHavingRaw($_GET['sql']); // unsafe
    $query->orderByRaw($_GET['sql']); // unsafe
    $query->groupByRaw($_GET['sql']); // unsafe
    $query->selectRaw($_GET['sql']); // unsafe
    $query->fromRaw($_GET['sql']); // unsafe
}

/**
 * @param EloquentBuilder<Event> $query
 */
function eloquentBuilderCases(EloquentBuilder $query): void
{
    $query->whereRaw($_GET['sql']); // unsafe
    $query->orWhereRaw($_GET['sql']); // unsafe
    $query->havingRaw($_GET['sql']); // unsafe
    $query->orHavingRaw($_GET['sql']); // unsafe
    $query->orderByRaw($_GET['sql']); // unsafe
    $query->groupByRaw($_GET['sql']); // unsafe
    $query->selectRaw($_GET['sql']); // unsafe
    $query->fromRaw($_GET['sql']); // unsafe

    Event::query()->orderByRaw($_GET['sort']); // unsafe
}

function safe(ConnectionInterface $connection, Builder $query): void
{
    $connection->select('SELECT * FROM users WHERE id = ?', [$_GET['id']]); // safe (bindings)
    $query->whereRaw('id = ?', [$_GET['id']]); // safe (bindings)
    $query->where('name', $_GET['name']); // safe (not a sink)
}
