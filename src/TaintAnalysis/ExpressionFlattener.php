<?php

declare(strict_types=1);

namespace NthRoot\PhpstanSecurity\TaintAnalysis;

use PhpParser\Node\Expr;
use PhpParser\Node\Expr\ArrayDimFetch;
use PhpParser\Node\Expr\Variable;

use function in_array;
use function is_string;
use function sprintf;

final readonly class ExpressionFlattener
{
    private const SUPERGLOBALS = ['_GET', '_POST'];

    /**
     * @return string[]
     */
    public function flatten(Expr $expr): array
    {
        if ($expr instanceof Variable && is_string($expr->name) && in_array($expr->name, self::SUPERGLOBALS, true)) {
            return [sprintf('source:%s', $expr->name)];
        }

        if ($expr instanceof ArrayDimFetch) {
            return $this->flatten($expr->var);
        }

        return [];
    }
}
