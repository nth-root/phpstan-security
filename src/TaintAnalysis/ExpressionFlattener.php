<?php

declare(strict_types=1);

namespace NthRoot\PhpstanSecurity\TaintAnalysis;

use PhpParser\Node\Expr;
use PhpParser\Node\Expr\ArrayDimFetch;
use PhpParser\Node\Expr\BinaryOp\Coalesce;
use PhpParser\Node\Expr\BinaryOp\Concat;
use PhpParser\Node\Expr\FuncCall;
use PhpParser\Node\Expr\Ternary;
use PhpParser\Node\Expr\Variable;
use PhpParser\Node\Name;
use PhpParser\Node\Scalar\InterpolatedString;
use PHPStan\Analyser\Scope;
use PHPStan\Reflection\ReflectionProvider;

use function array_key_exists;
use function in_array;
use function is_string;

final readonly class ExpressionFlattener
{
    private const SUPERGLOBALS = ['_GET', '_POST', '_REQUEST', '_COOKIE'];

    /**
     * Parameter name => position for arguments that end up in the return value. Null: all arguments.
     */
    private const PASS_THROUGH_FUNCTIONS = [
        'trim' => ['string' => 0],
        'ltrim' => ['string' => 0],
        'rtrim' => ['string' => 0],
        'strtolower' => ['string' => 0],
        'strtoupper' => ['string' => 0],
        'str_replace' => ['replace' => 1, 'subject' => 2],
        'sprintf' => null,
        'implode' => ['separator' => 0, 'array' => 1],
        'explode' => ['string' => 1],
    ];

    public function __construct(private ReflectionProvider $reflectionProvider) {}

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

        if ($expr instanceof Coalesce) {
            return [...$this->flatten($expr->left, $scope), ...$this->flatten($expr->right, $scope)];
        }

        if ($expr instanceof Ternary) {
            return [...$this->flatten($expr->if ?? $expr->cond, $scope), ...$this->flatten($expr->else, $scope)];
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

        if ($expr instanceof FuncCall && $expr->name instanceof Name && !$expr->isFirstClassCallable()) {
            return $this->flattenFunctionCall($expr, $expr->name, $scope);
        }

        return [];
    }

    /**
     * @return string[]
     */
    private function flattenFunctionCall(FuncCall $call, Name $name, Scope $scope): array
    {
        $functionName = $this->reflectionProvider->resolveFunctionName($name, $scope);

        if ($functionName === null || !array_key_exists($functionName, self::PASS_THROUGH_FUNCTIONS)) {
            return [];
        }

        $parameters = self::PASS_THROUGH_FUNCTIONS[$functionName];

        if ($parameters === null) {
            $args = $call->getArgs();
        } else {
            $args = [];

            foreach ($parameters as $parameter => $position) {
                $arg = $call->getArg($parameter, $position);

                if ($arg !== null) {
                    $args[] = $arg;
                }
            }
        }

        $nodes = [];

        foreach ($args as $arg) {
            $nodes = [...$nodes, ...$this->flatten($arg->value, $scope)];
        }

        return $nodes;
    }
}
