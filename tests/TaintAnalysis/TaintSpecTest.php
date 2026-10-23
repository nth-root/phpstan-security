<?php

declare(strict_types=1);

namespace NthRoot\PhpstanSecurity\Tests\TaintAnalysis;

use NthRoot\PhpstanSecurity\TaintAnalysis\SinkType;
use NthRoot\PhpstanSecurity\TaintAnalysis\TaintSpec;
use PHPStan\Reflection\ClassReflection;
use PHPStan\Testing\PHPStanTestCase;

class TaintSpecTest extends PHPStanTestCase
{
    private TaintSpec $spec;

    protected function setUp(): void
    {
        $this->spec = new TaintSpec([
            'sources' => [
                'variables' => ['_GET'],
                'methods' => ['Random\Randomizer' => ['getBytes']],
            ],
            'flows' => [
                'functions' => ['trim' => ['string']],
            ],
            'sinks' => [
                'functions' => ['exec' => ['type' => 'shell', 'parameters' => ['command']]],
                'methods' => ['Exception' => ['getMessage' => ['type' => 'html', 'parameters' => []]]],
            ],
        ]);
    }

    public function testReturnsVariableSources(): void
    {
        $this->assertSame('$_GET', $this->spec->getVariableSource('_GET'));
        $this->assertNull($this->spec->getVariableSource('_SERVER'));
    }

    public function testNamesMethodSourcesAfterTheConfiguredClassAndMethod(): void
    {
        $this->assertSame('Randomizer::getBytes()', $this->spec->getMethodSource($this->class('Random\Randomizer'), 'GETBYTES'));
        $this->assertNull($this->spec->getMethodSource($this->class('Random\Randomizer'), 'getInt'));
    }

    public function testFunctionsAreCaseInsensitive(): void
    {
        $this->assertSame(['string'], $this->spec->getFunctionFlows('TRIM'));
        $this->assertSame(SinkType::Shell, $this->spec->getFunctionSink('Exec')?->type);
        $this->assertSame(['command'], $this->spec->getFunctionSink('exec')?->parameters);
        $this->assertNull($this->spec->getFunctionSink('system'));
    }

    public function testMethodSinksMatchSubclasses(): void
    {
        $this->assertSame(SinkType::Html, $this->spec->getMethodSink($this->class('Exception'), 'getmessage')?->type);
        $this->assertSame(SinkType::Html, $this->spec->getMethodSink($this->class('RuntimeException'), 'getMessage')?->type);
        $this->assertNull($this->spec->getMethodSink($this->class('Error'), 'getMessage'));
    }

    private function class(string $name): ClassReflection
    {
        return self::createReflectionProvider()->getClass($name);
    }
}
