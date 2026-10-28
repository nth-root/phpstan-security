<?php

declare(strict_types=1);

namespace NthRoot\PhpstanSecurity\TaintAnalysis\Collector;

use NthRoot\PhpstanSecurity\TaintAnalysis\FunctionKey;
use NthRoot\PhpstanSecurity\TaintAnalysis\TaintNode;
use PhpParser\Node;
use PHPStan\Analyser\Scope;
use PHPStan\Collectors\Collector;
use PHPStan\Node\InClassMethodNode;
use PHPStan\Reflection\AttributeReflection;
use PHPStan\Reflection\ExtendedParameterReflection;
use PHPStan\Reflection\ReflectionProvider;
use Symfony\Component\Routing\Attribute\Route;

use function array_filter;
use function array_values;
use function preg_match_all;
use function sprintf;

/**
 * @implements Collector<InClassMethodNode, list<array{to: string, from: string[]}>>
 */
final readonly class SymfonyRouteParameterCollector implements Collector
{
    public function __construct(private ReflectionProvider $reflectionProvider) {}

    public function getNodeType(): string
    {
        return InClassMethodNode::class;
    }

    public function processNode(Node $node, Scope $scope): ?array
    {
        $method = $node->getMethodReflection();

        $route = $this->findRoute($method->getAttributes());

        if ($route === null) {
            return null;
        }

        $placeholders = $this->getPlaceholders($route);

        $classRoute = $this->findRoute($node->getClassReflection()->getAttributes());

        if ($classRoute !== null) {
            $placeholders = [...$placeholders, ...$this->getPlaceholders($classRoute)];
        }

        $assignments = array_map(
            function (ExtendedParameterReflection $parameter) use ($scope, $placeholders) {
                $name = $parameter->getName();

                if (!isset($placeholders[$name])) {
                    return null;
                }

                return [
                    'to' => TaintNode::variable(FunctionKey::of($scope), $name)->toString(),
                    'from' => [TaintNode::source(sprintf('route parameter {%s}', $name))->toString()],
                ];
            },
            $method->getOnlyVariant()->getParameters()
        );

        $assignments = array_values(array_filter($assignments));

        return $assignments === [] ? null : $assignments;
    }

    /**
     * @param AttributeReflection[] $attributes
     */
    private function findRoute(array $attributes): ?AttributeReflection
    {
        foreach ($attributes as $attribute) {
            if (!$this->reflectionProvider->hasClass($attribute->getName())) {
                continue;
            }

            if ($this->reflectionProvider->getClass($attribute->getName())->is(Route::class)) {
                return $attribute;
            }
        }

        return null;
    }

    /**
     * @return array<string, true>
     */
    private function getPlaceholders(AttributeReflection $route): array
    {
        $path = $route->getArgumentTypes()['path'] ?? null;

        if ($path === null) {
            return [];
        }

        $strings = $path->getConstantStrings();

        foreach ($path->getConstantArrays() as $array) {
            foreach ($array->getValueTypes() as $value) {
                $strings = [...$strings, ...$value->getConstantStrings()];
            }
        }

        $placeholders = [];

        foreach ($strings as $string) {
            preg_match_all('#\{!?(\w+)#', $string->getValue(), $matches);

            foreach ($matches[1] as $name) {
                $placeholders[$name] = true;
            }
        }

        return $placeholders;
    }
}
