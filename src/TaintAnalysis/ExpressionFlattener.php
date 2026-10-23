<?php

declare(strict_types=1);

namespace NthRoot\PhpstanSecurity\TaintAnalysis;

use PhpParser\Node\Expr;
use PhpParser\Node\Expr\ArrayDimFetch;
use PhpParser\Node\Expr\BinaryOp\Coalesce;
use PhpParser\Node\Expr\BinaryOp\Concat;
use PhpParser\Node\Expr\FuncCall;
use PhpParser\Node\Expr\MethodCall;
use PhpParser\Node\Expr\Ternary;
use PhpParser\Node\Expr\Variable;
use PhpParser\Node\Identifier;
use PhpParser\Node\Name;
use PhpParser\Node\Scalar\InterpolatedString;
use PHPStan\Analyser\Scope;
use PHPStan\Reflection\ReflectionProvider;
use PHPStan\Type\TypeCombinator;

use function is_string;

final readonly class ExpressionFlattener
{
    public function __construct(
        private ReflectionProvider $reflectionProvider,
        private CallArguments $callArguments,
        private TaintSpec $taintSpec
    ) {}

    /**
     * @return string[]
     */
    public function flatten(Expr $expr, Scope $scope): array
    {
        if ($expr instanceof Variable && is_string($expr->name)) {
            $source = $this->taintSpec->getVariableSource($expr->name);

            if ($source !== null) {
                return [TaintNode::source($source)->toString()];
            }

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

        if ($expr instanceof MethodCall && $expr->name instanceof Identifier && !$expr->isFirstClassCallable()) {
            return $this->flattenMethodCall($expr, $expr->name, $scope);
        }

        return [];
    }

    /**
     * @return string[]
     */
    private function flattenFunctionCall(FuncCall $call, Name $name, Scope $scope): array
    {
        $functionName = $this->reflectionProvider->resolveFunctionName($name, $scope);
        $flow = $functionName === null ? null : $this->taintSpec->getFunctionFlows($functionName);

        if ($flow === null) {
            return [];
        }

        $nodes = [];

        foreach ($this->callArguments->ofFunctionCall($call, $name, $scope, $flow) as $arg) {
            $nodes = [...$nodes, ...$this->flatten($arg, $scope)];
        }

        return $nodes;
    }

    /**
     * @return string[]
     */
    private function flattenMethodCall(MethodCall $call, Identifier $name, Scope $scope): array
    {
        $receiverType = TypeCombinator::removeNull($scope->getType($call->var));

        $nodes = [];

        foreach ($receiverType->getObjectClassReflections() as $class) {
            $source = $this->taintSpec->getMethodSource($class, $name->toString());

            if ($source !== null) {
                $nodes[] = TaintNode::source($source)->toString();
            }
        }

        return $nodes;
    }
}
