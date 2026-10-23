<?php

declare(strict_types=1);

function unsafeArgument(string $command): void
{
    exec($command); // unsafe (called with $_GET)
}

function safeArgument(string $command): void
{
    exec($command); // safe (only called with a constant argument)
}

function unsafeVariadicArgument(string ...$commands): void
{
    exec($commands[0]); // unsafe
}

function unsafeNamedArguments(string $label, string $command): void
{
    exec($command); // unsafe
    echo $label; // safe (only $command is tainted)
}

function unsafeSpreadArgument(string $label, string $command): void
{
    exec($command); // unsafe
}

function functionCalls(): void
{
    unsafeArgument($_GET['cmd']);
    safeArgument('ls');
    unsafeVariadicArgument('ls', $_GET['cmd']);
    unsafeNamedArguments(command: $_GET['cmd'], label: 'files');
    unsafeSpreadArgument(...$_GET['args']);
}

class UnsafeClass
{
    public function __construct(string $command)
    {
        exec($command); // unsafe
    }

    public function run(string $command): void
    {
        exec($command); // unsafe
    }

    public static function runStatic(string $command): void
    {
        exec($command); // unsafe
    }

    public function delegate(string $command): void
    {
        self::delegated($command);
    }

    private static function delegated(string $command): void
    {
        exec($command); // unsafe
    }
}

class UnsafeSubclass extends UnsafeClass {}

trait UnsafeTrait
{
    public function runFromTrait(string $command): void
    {
        exec($command); // unsafe
    }
}

class UnsafeTraitUser
{
    use UnsafeTrait;
}

class UnsafeUnionA
{
    public function handle(string $command): void
    {
        exec($command); // unsafe
    }
}

class UnsafeUnionB
{
    public function handle(string $command): void
    {
        exec($command); // unsafe
    }
}

function methodCalls(UnsafeClass $class, UnsafeSubclass $subclass, UnsafeTraitUser $traitUser, UnsafeUnionA|UnsafeUnionB $union): void
{
    $class->run($_GET['cmd']);
    UnsafeClass::runStatic($_GET['cmd']);
    $class->delegate($_GET['cmd']);
    new UnsafeClass($_GET['cmd']);
    $subclass->run($_GET['cmd']);
    $traitUser->runFromTrait($_GET['cmd']);
    $union->handle($_GET['cmd']);
}
