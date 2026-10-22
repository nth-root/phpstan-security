<?php

declare(strict_types=1);

namespace NthRoot\PhpstanSecurity\TaintAnalysis;

use PhpParser\Node\Arg;
use PhpParser\Node\Expr;
use PhpParser\Node\Expr\FuncCall;
use PhpParser\Node\Expr\MethodCall;
use PhpParser\Node\Name;
use PHPStan\Analyser\ArgumentsNormalizer;
use PHPStan\Analyser\Scope;
use PHPStan\Reflection\ExtendedMethodReflection;
use PHPStan\Reflection\ParametersAcceptor;
use PHPStan\Reflection\ParametersAcceptorSelector;
use PHPStan\Reflection\ReflectionProvider;

use function array_slice;
use function in_array;

final readonly class CallArguments
{
    public function __construct(private ReflectionProvider $reflectionProvider) {}

    /**
     * @param string[] $parameterNames
     *
     * @return Expr[]
     */
    public function ofFunctionCall(FuncCall $call, Name $name, Scope $scope, array $parameterNames): array
    {
        $function = $this->reflectionProvider->getFunction($name, $scope);

        $parametersAcceptor = ParametersAcceptorSelector::selectFromArgs(
            $scope,
            $call->getArgs(),
            $function->getVariants(),
            $function->getNamedArgumentsVariants()
        );

        $normalizedCall = ArgumentsNormalizer::reorderFuncArguments($parametersAcceptor, $call);

        if ($normalizedCall === null) {
            return [];
        }

        return $this->select($parametersAcceptor, $normalizedCall->getArgs(), $parameterNames);
    }

    /**
     * @param string[] $parameterNames
     *
     * @return Expr[]
     */
    public function ofMethodCall(
        MethodCall $call,
        ExtendedMethodReflection $method,
        Scope $scope,
        array $parameterNames
    ): array {
        $parametersAcceptor = ParametersAcceptorSelector::selectFromArgs(
            $scope,
            $call->getArgs(),
            $method->getVariants(),
            $method->getNamedArgumentsVariants()
        );

        $args = ArgumentsNormalizer::reorderArgs($parametersAcceptor, $call->getArgs());

        if ($args === null) {
            return [];
        }

        return $this->select($parametersAcceptor, $args, $parameterNames);
    }

    /**
     * @param string[] $parameterNames
     * @param Arg[]    $args
     *
     * @return Expr[]
     */
    private function select(
        ParametersAcceptor $parametersAcceptor,
        array $args,
        array $parameterNames
    ): array {
        $selected = [];

        foreach ($parametersAcceptor->getParameters() as $position => $parameter) {
            if (!in_array($parameter->getName(), $parameterNames, true)) {
                continue;
            }

            $length = $parameter->isVariadic() ? null : 1;
            $matching = array_slice($args, $position, $length);

            foreach ($matching as $arg) {
                $selected[] = $arg->value;
            }
        }

        return $selected;
    }
}
