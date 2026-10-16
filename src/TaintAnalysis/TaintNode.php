<?php

declare(strict_types=1);

namespace NthRoot\PhpstanSecurity\TaintAnalysis;

use function explode;
use function implode;
use function sprintf;

final readonly class TaintNode
{
    public function __construct(public NodeKind $kind, public string $name)
    {
    }

    public static function fromString(string $id): self
    {
        [$kind, $name] = explode(':', $id, 2);

        return new self(NodeKind::from($kind), $name);
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
        };
    }
}
