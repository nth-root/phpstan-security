<?php

declare(strict_types=1);

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
