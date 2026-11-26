<?php

declare(strict_types=1);

final class SameMethod
{
    private string $query = '';

    public function run(): void
    {
        $this->query = $_GET['q'];
        exec($this->query); // unsafe
    }
}

final class InstanceProperty
{
    private string $query;

    public function __construct()
    {
        $this->query = $_GET['q'];
    }

    public function run(): void
    {
        exec('grep ' . $this->query); // unsafe, across methods
    }
}

final class StaticProperty
{
    private static string $query = '';

    public static function set(): void
    {
        self::$query = $_GET['q'];
    }

    public static function run(): void
    {
        exec(static::$query); // unsafe
    }
}

final class ArrayProperty
{
    /** @var string[] */
    private array $args = [];

    public function add(): void
    {
        $this->args[] = $_GET['q'];
    }

    public function run(): void
    {
        exec(implode(' ', $this->args)); // unsafe
    }
}

class ParentWithProperty
{
    protected string $query = '';
}

final class ChildWritesFromSource extends ParentWithProperty
{
    public function set(): void
    {
        $this->query = $_GET['q'];
    }
}

final class ChildPassesToSink extends ParentWithProperty
{
    public function run(): void
    {
        exec($this->query); // unsafe
    }
}

final class Dto
{
    public string $query = '';
}

function externalReceiver(Dto $dto): void
{
    $dto->query = $_GET['q'];
}

function readsDto(Dto $dto): void
{
    exec($dto->query); // unsafe
}

final class IntProperty
{
    private int $id = 0;

    public function set(): void
    {
        $this->id = $_GET['id'];
    }

    public function run(): void
    {
        exec('kill ' . $this->id); // safe
    }
}

final class UntouchedProperty
{
    private string $command = 'ls';

    public function run(): void
    {
        exec($this->command); // safe
    }
}
