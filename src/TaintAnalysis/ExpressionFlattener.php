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

use function in_array;
use function is_string;

final readonly class ExpressionFlattener
{
    private const SUPERGLOBALS = ['_GET', '_POST', '_REQUEST', '_COOKIE'];

    private const PASS_THROUGH_FUNCTIONS = [
        'trim' => ['string'],
        'ltrim' => ['string'],
        'rtrim' => ['string'],
        'strtolower' => ['string'],
        'strtoupper' => ['string'],
        'str_replace' => ['replace', 'subject'],
        'sprintf' => ['format', 'values'],
        'implode' => ['separator', 'array'],
        'explode' => ['string'],
    ];

    private const SOURCE_METHODS = [
        'Symfony\Component\HttpFoundation\Request' => [
            'get' => 'Request::get()',
            'getcontent' => 'Request::getContent()',
            'toarray' => 'Request::toArray()',
        ],
    ];

    public function __construct(private ReflectionProvider $reflectionProvider, private CallArguments $callArguments) {}

    /**
     * @return string[]
     */
    public function flatten(Expr $expr, Scope $scope): array
    {
        if ($expr instanceof Variable && is_string($expr->name) && in_array($expr->name, self::SUPERGLOBALS, true)) {
            return [TaintNode::source('$' . $expr->name)->toString()];
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

        if ($functionName === null || !isset(self::PASS_THROUGH_FUNCTIONS[$functionName])) {
            return [];
        }

        $nodes = [];

        foreach ($this->callArguments->ofFunctionCall($call, $name, $scope, self::PASS_THROUGH_FUNCTIONS[$functionName]) as $arg) {
            $nodes = [...$nodes, ...$this->flatten($arg, $scope)];
        }

        return $nodes;
    }

    /**
     * @return string[]
     */
    private function flattenMethodCall(MethodCall $call, Identifier $name, Scope $scope): array
    {
        $methodName = $name->toLowerString();
        $receiverType = TypeCombinator::removeNull($scope->getType($call->var));

        $nodes = [];

        foreach ($receiverType->getObjectClassReflections() as $class) {
            foreach (self::SOURCE_METHODS as $className => $sourceMethods) {
                if (isset($sourceMethods[$methodName]) && $class->is($className)) {
                    $nodes[] = TaintNode::source($sourceMethods[$methodName])->toString();
                }
            }
        }

        return $nodes;
    }
}
