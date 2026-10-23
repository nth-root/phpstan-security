<?php

declare(strict_types=1);

namespace NthRoot\PhpstanSecurity\TaintAnalysis;

use PhpParser\Node\Expr\CallLike;
use PhpParser\Node\Expr\FuncCall;
use PhpParser\Node\Expr\MethodCall;
use PhpParser\Node\Expr\New_;
use PhpParser\Node\Expr\StaticCall;
use PhpParser\Node\Identifier;
use PhpParser\Node\Name;
use PHPStan\Analyser\Scope;
use PHPStan\Reflection\ClassReflection;
use PHPStan\Reflection\ExtendedMethodReflection;
use PHPStan\Reflection\FunctionReflection;
use PHPStan\Reflection\ReflectionProvider;
use PHPStan\Type\Type;
use PHPStan\Type\TypeCombinator;

final readonly class Callees
{
    public function __construct(private ReflectionProvider $reflectionProvider) {}

    /**
     * @return array<string, FunctionReflection|ExtendedMethodReflection>
     */
    public function of(CallLike $call, Scope $scope): array
    {
        return match (true) {
            $call->isFirstClassCallable() => [],
            $call instanceof FuncCall => $this->function($call, $scope),
            $call instanceof MethodCall && $call->name instanceof Identifier => $this->methods(
                $this->removeNull($call, $scope)->getObjectClassReflections(),
                $call->name->toString(),
                $scope
            ),
            $call instanceof StaticCall && $call->class instanceof Name && $call->name instanceof Identifier => $this->methods(
                $this->classes($call->class, $scope),
                $call->name->toString(),
                $scope
            ),
            $call instanceof New_ && $call->class instanceof Name => $this->methods(
                $this->classes($call->class, $scope),
                '__construct',
                $scope
            ),
            default => [],
        };
    }

    /**
     * @return array<string, FunctionReflection>
     */
    private function function(FuncCall $call, Scope $scope): array
    {
        if (!$call->name instanceof Name) {
            return [];
        }

        if (!$this->reflectionProvider->hasFunction($call->name, $scope)) {
            return [];
        }

        $function = $this->reflectionProvider->getFunction($call->name, $scope);

        if ($function->isBuiltin()) {
            return [];
        }

        return [$function->getName() => $function];
    }

    private function removeNull(MethodCall $call, Scope $scope): Type
    {
        return TypeCombinator::removeNull($scope->getType($call->var));
    }

    /**
     * @param ClassReflection[] $classes
     *
     * @return array<string, ExtendedMethodReflection>
     */
    private function methods(array $classes, string $name, Scope $scope): array
    {
        $methods = [];

        foreach ($classes as $class) {
            if (!$class->hasMethod($name)) {
                continue;
            }

            $method = $class->getMethod($name, $scope);

            if ($method->getDeclaringClass()->isBuiltin()) {
                continue;
            }

            $methods[FunctionKey::ofMethod($method)] = $method;
        }

        return $methods;
    }

    /**
     * @return ClassReflection[]
     */
    private function classes(Name $class, Scope $scope): array
    {
        $className = $scope->resolveName($class);

        if (!$this->reflectionProvider->hasClass($className)) {
            return [];
        }

        return [$this->reflectionProvider->getClass($className)];
    }
}
