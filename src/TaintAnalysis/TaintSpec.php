<?php

declare(strict_types=1);

namespace NthRoot\PhpstanSecurity\TaintAnalysis;

use PHPStan\Reflection\ClassReflection;

use function array_change_key_case;
use function explode;
use function sprintf;
use function strtolower;

use const CASE_LOWER;

/**
 * @phpstan-type TaintConfig array{
 *     sources: array{variables: string[], methods: array<string, string[]>},
 *     flows: array{functions: array<string, string[]>},
 *     sinks: array{functions: array<string, SinkConfig>, methods: array<string, array<string, SinkConfig>>},
 * }
 * @phpstan-type SinkConfig array{type: value-of<SinkType>, parameters: string[]}
 */
final readonly class TaintSpec
{
    /**
     * @var string[]
     */
    private array $sourceVariables;

    /**
     * @var array<string, array<lowercase-string, string>>
     */
    private array $sourceMethods;

    /**
     * @var array<lowercase-string, string[]>
     */
    private array $functionFlows;

    /**
     * @var array<lowercase-string, Sink>
     */
    private array $functionSinks;

    /**
     * @var array<string, array<lowercase-string, Sink>>
     */
    private array $methodSinks;

    /**
     * @param TaintConfig $config
     */
    public function __construct(array $config)
    {
        $sourceMethods = $methodSinks = $functionSinks = [];

        $this->sourceVariables = $config['sources']['variables'];

        foreach ($config['sources']['methods'] as $class => $methods) {
            foreach ($methods as $method) {
                $sourceMethods[$class][strtolower($method)] = sprintf('%s::%s()', self::getShortName($class), $method);
            }
        }

        foreach ($config['sinks']['methods'] as $class => $methods) {
            foreach ($methods as $method => $sink) {
                $methodSinks[$class][strtolower($method)] = self::buildSink($sink);
            }
        }

        foreach ($config['sinks']['functions'] as $function => $sink) {
            $functionSinks[strtolower($function)] = self::buildSink($sink);
        }

        $this->sourceMethods = $sourceMethods;
        $this->functionFlows = array_change_key_case($config['flows']['functions'], CASE_LOWER);
        $this->functionSinks = $functionSinks;
        $this->methodSinks = $methodSinks;
    }

    public function getVariableSource(string $variable): ?string
    {
        return in_array($variable, $this->sourceVariables, true) ? '$' . $variable : null;
    }

    public function getMethodSource(ClassReflection $class, string $method): ?string
    {
        foreach ($this->sourceMethods as $className => $methods) {
            if (isset($methods[strtolower($method)]) && $class->is($className)) {
                return $methods[strtolower($method)];
            }
        }

        return null;
    }

    /**
     * @return ?string[] names of the parameters whose taint reaches the return value
     */
    public function getFunctionFlows(string $function): ?array
    {
        return $this->functionFlows[strtolower($function)] ?? null;
    }

    public function getFunctionSink(string $function): ?Sink
    {
        return $this->functionSinks[strtolower($function)] ?? null;
    }

    public function getMethodSink(ClassReflection $class, string $method): ?Sink
    {
        foreach ($this->methodSinks as $className => $methods) {
            if (isset($methods[strtolower($method)]) && $class->is($className)) {
                return $methods[strtolower($method)];
            }
        }

        return null;
    }

    /**
     * @param SinkConfig $sink
     */
    private static function buildSink(array $sink): Sink
    {
        return new Sink(SinkType::from($sink['type']), $sink['parameters']);
    }

    private static function getShortName(string $class): string
    {
        $parts = explode('\\', $class);
        return array_pop($parts);
    }
}
