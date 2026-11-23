<?php

declare(strict_types=1);

namespace NthRoot\PhpstanSecurity\TaintAnalysis;

final readonly class Flow
{
    /**
     * @param string[]   $parameters names of the parameters whose taint reaches the return value
     * @param SinkType[] $sanitizes  sink types the return value is safe for
     * @param bool       $valuesOnly whether the keys of array arguments never reach the return value
     */
    public function __construct(public array $parameters, public array $sanitizes, public bool $valuesOnly = false) {}
}
