<?php

declare(strict_types=1);

function elementsAssignment(): void
{
    $params['q'] = $_GET['q'];
    exec('grep ' . $params['q']); // unsafe
}

function wholeArrayRead(): void
{
    $args['q'] = $_GET['q'];
    exec(implode(' ', $args)); // unsafe
}

function appendedElement(): void
{
    $args = [];
    $args[] = $_GET['q'];
    exec(implode(' ', $args)); // unsafe
}

function nestedElement(): void
{
    $params['a']['b'] = $_GET['q'];
    exec($params['a']['b']); // unsafe
}

function dynamicKey(string $key): void
{
    $params[$key] = $_GET['q'];
    exec($params[$key]); // unsafe
}

function concatToElement(): void
{
    $params = ['cmd' => 'ls '];
    $params['cmd'] .= $_GET['dir'];
    exec($params['cmd']); // unsafe
}

function coalesceToElement(): void
{
    $params = [];
    $params['cmd'] ??= $_GET['cmd'];
    exec($params['cmd']); // unsafe
}

function taintedKey(): void
{
    $params[$_GET['key']] = 'value';

    foreach ($params as $key => $value) {
        exec("ls $key"); // unsafe
    }
}

function constantElement(): void
{
    $params['q'] = $_GET['q'];
    $params['limit'] = 10;
    exec('head -n ' . $params['limit']); // safe
}

function castElement(): void
{
    $params['n'] = (int) $_GET['n'];
    exec('head -n ' . $params['n']); // safe
}
