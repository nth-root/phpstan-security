<?php

declare(strict_types=1);

namespace NthRoot\PhpstanSecurity\TaintAnalysis;

use function explode;
use function implode;
use function sprintf;
use function strrpos;
use function substr;

final readonly class TaintNode
{
    public function __construct(public NodeKind $kind, public string $name) {}

    public static function fromString(string $id): self
    {
        [$kind, $name] = explode(':', $id, 2);

        return new self(NodeKind::from($kind), $name);
    }

    public static function source(string $name): self
    {
        return new self(NodeKind::Source, $name);
    }

    public static function variable(string $functionKey, string $variable): self
    {
        return new self(NodeKind::Variable, $functionKey . ':' . $variable);
    }

    public function isSource(): bool
    {
        return $this->kind === NodeKind::Source;
    }

    public function toString(): string
    {
        return implode(':', [$this->kind->value, $this->name]);
    }

    public function describe(): string
    {
        return match ($this->kind) {
            NodeKind::Source => sprintf('$%s', $this->name),
            NodeKind::Variable => substr($this->name, strrpos($this->name, ':') + 1),
        };
    }
}
