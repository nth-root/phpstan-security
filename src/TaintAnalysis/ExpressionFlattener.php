<?php

declare(strict_types=1);

namespace NthRoot\PhpstanSecurity\TaintAnalysis;

use PhpParser\Node\Expr;
use PhpParser\Node\Expr\ArrayDimFetch;
use PhpParser\Node\Expr\BinaryOp\Concat;
use PhpParser\Node\Expr\Variable;
use PhpParser\Node\Scalar\InterpolatedString;
use PHPStan\Analyser\Scope;

use function in_array;
use function is_string;

final readonly class ExpressionFlattener
{
    private const SUPERGLOBALS = ['_GET', '_POST'];

    /**
     * @return string[]
     */
    public function flatten(Expr $expr, Scope $scope): array
    {
        if ($expr instanceof Variable && is_string($expr->name) && in_array($expr->name, self::SUPERGLOBALS, true)) {
            return [TaintNode::source($expr->name)->toString()];
        }

        if ($expr instanceof Variable && is_string($expr->name)) {
            return [TaintNode::variable(FunctionKey::of($scope), $expr->name)->toString()];
        }

        if ($expr instanceof ArrayDimFetch) {
            return $this->flatten($expr->var, $scope);
        }

        if ($expr instanceof Concat) {
            return [...$this->flatten($expr->left, $scope), ...$this->flatten($expr->right, $scope)];
        }

        if ($expr instanceof InterpolatedString) {
            $nodes = [];

            foreach ($expr->parts as $part) {
                if ($part instanceof Expr) {
                    $nodes = [...$nodes, ...$this->flatten($part, $scope)];
                }
            }

            return $nodes;
        }

        return [];
    }
}
