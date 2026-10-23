<?php

declare(strict_types=1);

namespace NthRoot\PhpstanSecurity\TaintAnalysis;

final readonly class Sink
{
    /**
     * @param string[] $parameters
     */
    public function __construct(public SinkType $type, public array $parameters) {}
}
