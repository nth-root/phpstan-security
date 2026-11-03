<?php

declare(strict_types=1);

function taintedHelper(): string
{
    return $_GET['cmd'];
}

function constantHelper(): string
{
    return 'ls';
}

function intHelper(): int
{
    return $_GET['pid'];
}

function escapingHelper(): string
{
    return htmlspecialchars($_GET['name']);
}

function closureHelper(): string
{
    $callback = function () {
        return $_GET['cmd'];
    };

    return 'ls';
}

class ReturnHelper
{
    public function get(): string
    {
        return $_GET['cmd'];
    }

    public static function getStatic(): string
    {
        return $_GET['cmd'];
    }

    public function delegate(): string
    {
        return $this->get();
    }
}

class ReturnConsumer
{
    public function __construct(private ReturnHelper $helper) {}

    public function chained(): void
    {
        exec($this->helper->get()); // unsafe (through a property chain)
    }
}

function returnCases(ReturnHelper $helper): void
{
    exec(taintedHelper()); // unsafe
    exec(constantHelper()); // safe
    exec('kill ' . intHelper()); // safe (an int can't carry an injection)
    echo escapingHelper(); // safe
    exec(escapingHelper()); // unsafe (escaped for HTML, not the shell)
    exec(closureHelper()); // safe (the closure's return doesn't count)
    exec($helper->get()); // unsafe
    exec(ReturnHelper::getStatic()); // unsafe
    exec($helper->delegate()); // unsafe (returned through another method)

    $cmd = taintedHelper();
    exec($cmd); // unsafe (through a variable)
}
