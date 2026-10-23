<?php

declare(strict_types=1);

class Subclass extends PDO {}

class OverridingSubclass extends PDO
{
    public function exec(string $statement): int|false
    {
        return parent::exec($statement);
    }
}

class DependentClass
{
    public function __construct(private PDO $pdo) {}

    public function find(): void
    {
        $this->pdo->query('SELECT * FROM users WHERE id = ' . $_GET['id']); // unsafe (property receiver)
    }
}

function cases(PDO $pdo, ?PDO $nullablePdo, PDO|DateTime $union): void
{
    $pdo->query($_GET['sql']); // unsafe
    $pdo->exec($_GET['sql']); // unsafe
    $pdo->prepare($_GET['sql']); // unsafe
    $pdo->prepare(options: [], query: $_GET['sql']); // unsafe
    $nullablePdo?->query($_GET['sql']); // unsafe
    $nullablePdo->query($_GET['sql']); // unsafe
    $union->query($_GET['sql']); // unsafe
}

function safe(PDO $pdo, mixed $unknown): void
{
    $pdo->query('SELECT 1'); // safe
    $pdo->prepare('SELECT 1', $_GET['options']); // safe (only the query is a sink)
    $pdo->quote($_GET['value']); // safe (not a sink)
    $unknown->query($_GET['sql']); // safe (receiver type unknown)
}

function subclasses(Subclass $appPdo, OverridingSubclass $loggingPdo): void
{
    $appPdo->query($_GET['sql']); // unsafe (inherited from PDO)
    $loggingPdo->exec($_GET['sql']); // unsafe (overridden in LoggingPdo)
}
