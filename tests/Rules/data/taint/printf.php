<?php

declare(strict_types=1);

function cases(): void
{
    printf($_GET['format']); // unsafe (format)
    printf('%s', $_GET['name']); // unsafe (value)
    printf('%s %s', 'Hello', $_GET['name']); // unsafe (variadic value)
    printf('Hello %s', 'world'); // safe
    printf('%s', ...$_GET['names']); // unsafe
    vprintf($_GET['format']); // unsafe (format)
    vprintf('%s', $_GET['name']); // unsafe (value)
    sprintf('%s', $_GET['name']); // safe (returns the string, doesn't print it)
}
