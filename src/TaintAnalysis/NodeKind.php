<?php

declare(strict_types=1);

namespace NthRoot\PhpstanSecurity\TaintAnalysis;

enum NodeKind: string
{
    case Source = 'source';
    case Variable = 'var';
    case Property = 'prop';
    case Sanitized = 'sanitized';
    case Return = 'return';
}
