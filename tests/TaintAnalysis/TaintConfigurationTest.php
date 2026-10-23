<?php

declare(strict_types=1);

namespace NthRoot\PhpstanSecurity\Tests\TaintAnalysis;

use NthRoot\PhpstanSecurity\TaintAnalysis\TaintSpec;
use PhpParser\Node\Name;
use PHPStan\Analyser\OutOfClassScope;
use PHPStan\Reflection\ParametersAcceptor;
use PHPStan\Reflection\ReflectionProvider;
use PHPStan\Testing\PHPStanTestCase;
use PHPUnit\Framework\Attributes\DataProvider;

/**
 * @phpstan-import-type TaintConfig from TaintSpec
 */
class TaintConfigurationTest extends PHPStanTestCase
{
    private ReflectionProvider $reflectionProvider;

    public static function getAdditionalConfigFiles(): array
    {
        return [__DIR__ . '/../../extension.neon'];
    }

    protected function setUp(): void
    {
        $this->reflectionProvider = self::createReflectionProvider();
    }

    /**
     * @param string[] $parameters
     */
    #[DataProvider('getFunctions')]
    public function testConfiguredFunctionExists(string $function, array $parameters): void
    {
        $name = new Name($function);

        $this->assertTrue(
            $this->reflectionProvider->hasFunction($name, null),
            sprintf('Function %s() does not exist', $function)
        );

        $reflection = $this->reflectionProvider->getFunction($name, null);

        $this->assertParametersExist(sprintf('%s()', $function), $reflection->getVariants(), $parameters);
    }

    /**
     * @param string[] $parameters
     */
    #[DataProvider('getMethods')]
    public function testConfiguredMethodExists(string $class, string $method, array $parameters): void
    {
        $this->assertTrue($this->reflectionProvider->hasClass($class), sprintf('Class %s does not exist', $class));

        $classReflection = $this->reflectionProvider->getClass($class);

        $this->assertTrue(
            $classReflection->hasMethod($method),
            sprintf('Method %s::%s() does not exist', $class, $method)
        );

        $reflection = $classReflection->getMethod($method, new OutOfClassScope());

        $this->assertSame($reflection->getName(), $method, 'Method names must be written as declared');
        $this->assertParametersExist(sprintf('%s::%s()', $class, $method), $reflection->getVariants(), $parameters);
    }

    /**
     * @return iterable<string, array{string, string[]}>
     */
    public static function getFunctions(): iterable
    {
        foreach (self::getConfiguration()['flows']['functions'] as $function => $parameters) {
            yield sprintf('flow %s()', $function) => [$function, $parameters];
        }

        foreach (self::getConfiguration()['sinks']['functions'] as $function => $sink) {
            yield sprintf('sink %s()', $function) => [$function, $sink['parameters']];
        }
    }

    /**
     * @return iterable<string, array{string, string, string[]}>
     */
    public static function getMethods(): iterable
    {
        $configuration = self::getConfiguration();

        foreach ($configuration['sources']['methods'] as $class => $methods) {
            foreach ($methods as $method) {
                yield sprintf('source %s::%s()', $class, $method) => [$class, $method, []];
            }
        }

        foreach ($configuration['sinks']['methods'] as $class => $methods) {
            foreach ($methods as $method => $sink) {
                yield sprintf('sink %s::%s()', $class, $method) => [$class, $method, $sink['parameters']];
            }
        }
    }

    /**
     * @param ParametersAcceptor[] $variants
     * @param string[]             $parameters
     */
    private function assertParametersExist(string $callable, array $variants, array $parameters): void
    {
        $known = [];

        foreach ($variants as $variant) {
            foreach ($variant->getParameters() as $parameter) {
                $known[] = $parameter->getName();
            }
        }

        foreach ($parameters as $parameter) {
            $this->assertContains($parameter, $known, sprintf('%s has no parameter $%s', $callable, $parameter));
        }
    }

    /**
     * @return TaintConfig
     */
    private static function getConfiguration(): array
    {
        /** @var TaintConfig */
        return self::getContainer()->getParameter('taint');
    }
}
