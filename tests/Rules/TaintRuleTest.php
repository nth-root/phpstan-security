<?php

declare(strict_types=1);

namespace NthRoot\PhpstanSecurity\Tests\Rules;

use NthRoot\PhpstanSecurity\Rules\TaintRule;
use NthRoot\PhpstanSecurity\TaintAnalysis\Collector\AssignmentCollector;
use NthRoot\PhpstanSecurity\TaintAnalysis\Collector\CallArgumentCollector;
use NthRoot\PhpstanSecurity\TaintAnalysis\Collector\CompoundAssignmentCollector;
use NthRoot\PhpstanSecurity\TaintAnalysis\Collector\EchoSinkCollector;
use NthRoot\PhpstanSecurity\TaintAnalysis\Collector\FunctionCallSinkCollector;
use NthRoot\PhpstanSecurity\TaintAnalysis\Collector\HeaderSinkCollector;
use NthRoot\PhpstanSecurity\TaintAnalysis\Collector\IncludeSinkCollector;
use NthRoot\PhpstanSecurity\TaintAnalysis\Collector\MethodCallSinkCollector;
use NthRoot\PhpstanSecurity\TaintAnalysis\Collector\PrintSinkCollector;
use NthRoot\PhpstanSecurity\TaintAnalysis\Collector\ShellExecSinkCollector;
use NthRoot\PhpstanSecurity\TaintAnalysis\Collector\SymfonyRouteParameterCollector;
use NthRoot\PhpstanSecurity\TaintAnalysis\SinkType;
use PHPStan\Rules\Rule;
use PHPStan\Testing\RuleTestCase;

use function sprintf;

/**
 * @extends RuleTestCase<TaintRule>
 */
class TaintRuleTest extends RuleTestCase
{
    public static function getAdditionalConfigFiles(): array
    {
        return [__DIR__ . '/../../extension.neon'];
    }

    protected function getRule(): Rule
    {
        return new TaintRule();
    }

    protected function getCollectors(): array
    {
        $container = self::getContainer();

        return [
            $container->getByType(FunctionCallSinkCollector::class),
            $container->getByType(MethodCallSinkCollector::class),
            $container->getByType(HeaderSinkCollector::class),
            $container->getByType(AssignmentCollector::class),
            $container->getByType(CompoundAssignmentCollector::class),
            $container->getByType(CallArgumentCollector::class),
            $container->getByType(SymfonyRouteParameterCollector::class),
            $container->getByType(ShellExecSinkCollector::class),
            $container->getByType(EchoSinkCollector::class),
            $container->getByType(PrintSinkCollector::class),
            $container->getByType(IncludeSinkCollector::class),
        ];
    }

    public function testDetectsDirectUseOfTaintedValue(): void
    {
        $this->analyse([__DIR__ . '/data/taint/direct.php'], [
            [$this->getMessage(SinkType::Shell, '$_GET', 'exec()'), 9],
            [$this->getMessage(SinkType::Shell, '$_GET', 'exec()'), 13],
            [$this->getMessage(SinkType::Shell, '$_GET', 'exec()'), 16],
        ]);
    }

    public function testDetectsThroughLocalVariables(): void
    {
        $this->analyse([__DIR__ . '/data/taint/variables.php'], [
            [$this->getMessage(SinkType::Shell, '$_GET', 'exec()'), 8],
            [$this->getMessage(SinkType::Shell, '$_POST', 'system()'), 21],
        ]);
    }

    public function testDetectsThroughConcatenation(): void
    {
        $this->analyse([__DIR__ . '/data/taint/concatenation.php'], [
            [$this->getMessage(SinkType::Shell, '$_GET', 'exec()'), 7],
            [$this->getMessage(SinkType::Shell, '$_GET', 'exec()'), 13],
            [$this->getMessage(SinkType::Shell, '$_GET', 'exec()'), 19],
            [$this->getMessage(SinkType::Shell, '$_POST, $_GET', 'exec()'), 29],
            [$this->getMessage(SinkType::Shell, '$_GET', 'exec()'), 34],
        ]);
    }

    public function testDetectsThroughInterpolation(): void
    {
        $this->analyse([__DIR__ . '/data/taint/interpolation.php'], [
            [$this->getMessage(SinkType::Shell, '$_GET', 'exec()'), 8],
            [$this->getMessage(SinkType::Shell, '$_GET', 'exec()'), 9],
            [$this->getMessage(SinkType::Shell, '$_GET', 'exec()'), 16],
        ]);
    }

    public function testDetectsThroughTernaryConditions(): void
    {
        $this->analyse([__DIR__ . '/data/taint/conditional.php'], [
            [$this->getMessage(SinkType::Shell, '$_GET', 'exec()'), 7],
            [$this->getMessage(SinkType::Shell, '$_GET', 'exec()'), 8],
            [$this->getMessage(SinkType::Shell, '$_GET', 'exec()'), 9],
            [$this->getMessage(SinkType::Shell, '$_GET', 'exec()'), 10],
            [$this->getMessage(SinkType::Shell, '$_GET', 'exec()'), 12],
            [$this->getMessage(SinkType::Shell, '$_POST, $_GET', 'exec()'), 13],
            [$this->getMessage(SinkType::Shell, '$_GET', 'exec()'), 19],
        ]);
    }

    public function testDetectsShellFunctions(): void
    {
        $this->analyse([__DIR__ . '/data/taint/shell_functions.php'], [
            [$this->getMessage(SinkType::Shell, '$_GET', 'popen()'), 7],
            [$this->getMessage(SinkType::Shell, '$_GET', 'proc_open()'), 8],
            [$this->getMessage(SinkType::Shell, '$_GET', 'pcntl_exec()'), 9],
            [$this->getMessage(SinkType::Shell, '$_GET', 'pcntl_exec()'), 10],
        ]);
    }

    public function testDetectsUseOfBacktickOperator(): void
    {
        $this->analyse([__DIR__ . '/data/taint/shell_exec.php'], [
            [$this->getMessage(SinkType::Shell, '$_GET', 'the backtick operator'), 7],
            [$this->getMessage(SinkType::Shell, '$_GET', 'the backtick operator'), 13],
        ]);
    }

    public function testDetectsEchoAndPrint(): void
    {
        $this->analyse([__DIR__ . '/data/taint/html.php'], [
            [$this->getMessage(SinkType::Html, '$_GET', 'echo'), 7],
            [$this->getMessage(SinkType::Html, '$_GET', 'echo'), 9],
            [$this->getMessage(SinkType::Html, '$_POST', 'echo'), 10],
            [$this->getMessage(SinkType::Html, '$_GET', 'print'), 12],
            [$this->getMessage(SinkType::Html, '$_GET', 'echo'), 16],
            [$this->getMessage(SinkType::Html, '$_GET', 'echo'), 22],
        ]);
    }

    public function testDetectsPrintfFunctions(): void
    {
        $this->analyse([__DIR__ . '/data/taint/printf.php'], [
            [$this->getMessage(SinkType::Html, '$_GET', 'printf()'), 7],
            [$this->getMessage(SinkType::Html, '$_GET', 'printf()'), 8],
            [$this->getMessage(SinkType::Html, '$_GET', 'printf()'), 9],
            [$this->getMessage(SinkType::Html, '$_GET', 'printf()'), 11],
            [$this->getMessage(SinkType::Html, '$_GET', 'vprintf()'), 12],
            [$this->getMessage(SinkType::Html, '$_GET', 'vprintf()'), 13],
        ]);
    }

    public function testDetectsThroughPassThroughFunctions(): void
    {
        $this->analyse([__DIR__ . '/data/taint/passthrough.php'], [
            [$this->getMessage(SinkType::Shell, '$_GET', 'exec()'), 7],
            [$this->getMessage(SinkType::Shell, '$_GET', 'exec()'), 9],
            [$this->getMessage(SinkType::Shell, '$_GET', 'exec()'), 10],
            [$this->getMessage(SinkType::Shell, '$_GET', 'exec()'), 12],
            [$this->getMessage(SinkType::Shell, '$_GET', 'exec()'), 13],
            [$this->getMessage(SinkType::Shell, '$_GET', 'exec()'), 14],
            [$this->getMessage(SinkType::Shell, '$_GET', 'exec()'), 18],
            [$this->getMessage(SinkType::Shell, '$_GET', 'exec()'), 23],
            [$this->getMessage(SinkType::Shell, '$_GET', 'exec()'), 24],
        ]);
    }

    public function testDetectsThroughCompoundAssignment(): void
    {
        $this->analyse([__DIR__ . '/data/taint/compound_assignment.php'], [
            [$this->getMessage(SinkType::Shell, '$_GET', 'exec()'), 9],
            [$this->getMessage(SinkType::Shell, '$_GET', 'exec()'), 16],
            [$this->getMessage(SinkType::Html, '$_GET', 'echo'), 30],
        ]);
    }

    public function testDetectsMethodCallSinks(): void
    {
        $this->analyse([__DIR__ . '/data/taint/method_calls.php'], [
            [$this->getMessage(SinkType::Sql, '$_GET', 'PDO::query()'), 21],
            [$this->getMessage(SinkType::Sql, '$_GET', 'PDO::query()'), 27],
            [$this->getMessage(SinkType::Sql, '$_GET', 'PDO::exec()'), 28],
            [$this->getMessage(SinkType::Sql, '$_GET', 'PDO::prepare()'), 29],
            [$this->getMessage(SinkType::Sql, '$_GET', 'PDO::prepare()'), 30],
            [$this->getMessage(SinkType::Sql, '$_GET', 'PDO::query()'), 31],
            [$this->getMessage(SinkType::Sql, '$_GET', 'PDO::query()'), 32],
            [$this->getMessage(SinkType::Sql, '$_GET', 'PDO::query()'), 33],
            [$this->getMessage(SinkType::Sql, '$_GET', 'PDO::query()'), 46],
            [$this->getMessage(SinkType::Sql, '$_GET', 'OverridingSubclass::exec()'), 47],
        ]);
    }

    public function testDetectsDoctrineDbalSinks(): void
    {
        $this->analyse([__DIR__ . '/data/taint/dbal.php'], [
            [$this->getMessage(SinkType::Sql, '$_GET', 'Doctrine\DBAL\Connection::executeQuery()'), 9],
            [$this->getMessage(SinkType::Sql, '$_GET', 'Doctrine\DBAL\Connection::executeStatement()'), 10],
            [$this->getMessage(SinkType::Sql, '$_GET', 'Doctrine\DBAL\Connection::prepare()'), 11],
            [$this->getMessage(SinkType::Sql, '$_GET', 'Doctrine\DBAL\Connection::executeQuery()'), 12],
            [$this->getMessage(SinkType::Sql, '$_GET', 'Doctrine\DBAL\Connection::fetchOne()'), 13],
        ]);
    }

    public function testDetectsMysqliSinks(): void
    {
        $this->analyse([__DIR__ . '/data/taint/mysqli.php'], [
            [$this->getMessage(SinkType::Sql, '$_GET', 'mysqli_query()'), 7],
            [$this->getMessage(SinkType::Sql, '$_GET', 'mysqli_query()'), 8],
            [$this->getMessage(SinkType::Sql, '$_GET', 'mysqli::query()'), 13],
        ]);
    }

    public function testDetectsSqlite3Sinks(): void
    {
        $this->analyse([__DIR__ . '/data/taint/sqlite3.php'], [
            [$this->getMessage(SinkType::Sql, '$_GET', 'SQLite3::query()'), 7],
        ]);
    }

    public function testDetectsFileInclusion(): void
    {
        $this->analyse([__DIR__ . '/data/taint/include.php'], [
            [$this->getMessage(SinkType::FileInclusion, '$_GET', 'include'), 7],
            [$this->getMessage(SinkType::FileInclusion, '$_GET', 'include_once'), 8],
            [$this->getMessage(SinkType::FileInclusion, '$_GET', 'require'), 9],
            [$this->getMessage(SinkType::FileInclusion, '$_GET', 'require_once'), 10],
            [$this->getMessage(SinkType::FileInclusion, '$_GET', 'include'), 11],
            [$this->getMessage(SinkType::FileInclusion, '$_GET', 'include'), 12],
        ]);
    }

    public function testDetectsOpenRedirects(): void
    {
        $this->analyse([__DIR__ . '/data/taint/open_redirect.php'], [
            [$this->getMessage(SinkType::RedirectHeader, '$_GET', 'header()'), 7],
            [$this->getMessage(SinkType::RedirectHeader, '$_GET', 'header()'), 8],
            [$this->getMessage(SinkType::RedirectHeader, '$_GET', 'header()'), 9],
            [$this->getMessage(SinkType::RedirectHeader, '$_GET', 'header()'), 10],
            [$this->getMessage(SinkType::RedirectHeader, '$_GET', 'header()'), 11],
            [$this->getMessage(SinkType::RedirectHeader, '$_GET', 'header()'), 12],
            [$this->getMessage(SinkType::RedirectHeader, '$_GET', 'header()'), 15],
        ]);
    }

    public function testFollowsArgumentsIntoParameters(): void
    {
        $this->analyse([__DIR__ . '/data/taint/arguments.php'], [
            [$this->getMessage(SinkType::Shell, '$_GET', 'exec()'), 7],
            [$this->getMessage(SinkType::Shell, '$_GET', 'exec()'), 17],
            [$this->getMessage(SinkType::Shell, '$_GET', 'exec()'), 22],
            [$this->getMessage(SinkType::Shell, '$_GET', 'exec()'), 28],
            [$this->getMessage(SinkType::Shell, '$_GET', 'exec()'), 44],
            [$this->getMessage(SinkType::Shell, '$_GET', 'exec()'), 49],
            [$this->getMessage(SinkType::Shell, '$_GET', 'exec()'), 54],
            [$this->getMessage(SinkType::Shell, '$_GET', 'exec()'), 64],
            [$this->getMessage(SinkType::Shell, '$_GET', 'exec()'), 74],
            [$this->getMessage(SinkType::Shell, '$_GET', 'exec()'), 87],
            [$this->getMessage(SinkType::Shell, '$_GET', 'exec()'), 95],
        ]);
    }

    public function testDetectsSymfonyRequestSources(): void
    {
        $this->analyse([__DIR__ . '/data/taint/symfony_request.php'], [
            [$this->getMessage(SinkType::Shell, 'Request::get()', 'exec()'), 20],
            [$this->getMessage(SinkType::Shell, 'Request::getContent()', 'exec()'), 21],
            [$this->getMessage(SinkType::Shell, 'Request::toArray()', 'exec()'), 22],
            [$this->getMessage(SinkType::Shell, 'Request::get()', 'exec()'), 25],
            [$this->getMessage(SinkType::Shell, '$_GET, Request::get()', 'exec()'), 27],
            [$this->getMessage(SinkType::Shell, 'Request::get()', 'exec()'), 28],
            [$this->getMessage(SinkType::Shell, 'InputBag::get()', 'exec()'), 39],
            [$this->getMessage(SinkType::Shell, 'HeaderBag::get()', 'exec()'), 40],
            [$this->getMessage(SinkType::Shell, 'InputBag::all()', 'exec()'), 41],
            [$this->getMessage(SinkType::Shell, 'InputBag::get()', 'exec()'), 42],
            [$this->getMessage(SinkType::Shell, 'Request::getPathInfo()', 'exec()'), 58],
            [$this->getMessage(SinkType::Shell, 'Request::getRequestUri()', 'exec()'), 59],
            [$this->getMessage(SinkType::Shell, 'Request::getUri()', 'exec()'), 60],
            [$this->getMessage(SinkType::Shell, 'Request::getHost()', 'exec()'), 61],
            [$this->getMessage(SinkType::Shell, 'Request::getQueryString()', 'exec()'), 62],
        ]);
    }

    public function testDetectsSymfonyRouteParameters(): void
    {
        $this->analyse([__DIR__ . '/data/taint/symfony_route.php'], [
            [$this->getMessage(SinkType::Shell, 'route parameter {slug}', 'exec()'), 14],
            [$this->getMessage(SinkType::Shell, 'route parameter {locale}', 'exec()'), 15],
            [$this->getMessage(SinkType::Shell, 'route parameter {id}', 'exec()'), 21],
            [$this->getMessage(SinkType::Shell, 'route parameter {page}', 'exec()'), 22],
            [$this->getMessage(SinkType::Shell, 'route parameter {topic}', 'exec()'), 28],
            [$this->getMessage(SinkType::Shell, 'route parameter {onderwerp}', 'exec()'), 29],
            [$this->getMessage(SinkType::Shell, 'route parameter {name}', 'exec()'), 35],
        ]);
    }

    public function testDetectsLaravelRequestSources(): void
    {
        $this->analyse([__DIR__ . '/data/taint/laravel_request.php'], [
            [$this->getMessage(SinkType::Shell, 'Request::input()', 'exec()'), 11],
            [$this->getMessage(SinkType::Shell, 'Request::query()', 'exec()'), 12],
            [$this->getMessage(SinkType::Shell, 'Request::post()', 'exec()'), 13],
            [$this->getMessage(SinkType::Shell, 'Request::cookie()', 'exec()'), 14],
            [$this->getMessage(SinkType::Shell, 'Request::header()', 'exec()'), 15],
            [$this->getMessage(SinkType::Shell, 'Request::server()', 'exec()'), 16],
            [$this->getMessage(SinkType::Shell, 'Request::json()', 'exec()'), 17],
            [$this->getMessage(SinkType::Shell, 'Request::route()', 'exec()'), 18],
            [$this->getMessage(SinkType::Shell, 'Request::string()', 'exec()'), 19],

            [$this->getMessage(SinkType::Shell, 'Request::all()', 'exec()'), 21],
            [$this->getMessage(SinkType::Shell, 'Request::only()', 'exec()'), 22],
            [$this->getMessage(SinkType::Shell, 'Request::except()', 'exec()'), 23],
            [$this->getMessage(SinkType::Shell, 'Request::keys()', 'exec()'), 24],

            [$this->getMessage(SinkType::Shell, 'Request::getContent()', 'exec()'), 27],
            [$this->getMessage(SinkType::Shell, 'Request::input()', 'exec()'), 29],

            [$this->getMessage(SinkType::Shell, 'Request::segment()', 'exec()'), 47],
            [$this->getMessage(SinkType::Shell, 'Request::segments()', 'exec()'), 48],
            [$this->getMessage(SinkType::Shell, 'Request::path()', 'exec()'), 49],
            [$this->getMessage(SinkType::Shell, 'Request::decodedPath()', 'exec()'), 50],
            [$this->getMessage(SinkType::Shell, 'Request::url()', 'exec()'), 51],
            [$this->getMessage(SinkType::Shell, 'Request::fullUrl()', 'exec()'), 52],
            [$this->getMessage(SinkType::Shell, 'Request::fullUrlWithQuery()', 'exec()'), 53],
            [$this->getMessage(SinkType::Shell, 'Request::fullUrlWithoutQuery()', 'exec()'), 54],
            [$this->getMessage(SinkType::Shell, 'Request::host()', 'exec()'), 55],
            [$this->getMessage(SinkType::Shell, 'Request::httpHost()', 'exec()'), 56],
            [$this->getMessage(SinkType::Shell, 'Request::schemeAndHttpHost()', 'exec()'), 57],
            [$this->getMessage(SinkType::Shell, 'Request::root()', 'exec()'), 58],

            [$this->getMessage(SinkType::Shell, 'Request::userAgent()', 'exec()'), 63],
            [$this->getMessage(SinkType::Shell, 'Request::bearerToken()', 'exec()'), 64],
            [$this->getMessage(SinkType::Shell, 'Request::old()', 'exec()'), 65],
        ]);
    }

    public function testFollowsArgumentsAcrossFiles(): void
    {
        $this->analyse([
            __DIR__ . '/data/taint/arguments_controller.php',
            __DIR__ . '/data/taint/arguments_repository.php',
        ], [
            [$this->getMessage(SinkType::Sql, '$_GET', 'PDO::query()'), 11],
        ]);
    }

    public function testDetectsFileAccess(): void
    {
        $this->analyse([__DIR__ . '/data/taint/file.php'], [
            [$this->getMessage(SinkType::FilePath, '$_GET', 'file_get_contents()'), 7],
            [$this->getMessage(SinkType::FilePath, '$_GET', 'file_get_contents()'), 8],
            [$this->getMessage(SinkType::FilePath, '$_GET', 'copy()'), 9],
        ]);
    }

    private function getMessage(SinkType $sinkType, string $source, string $sink): string
    {
        return sprintf(
            'Possible %s: tainted value from %s is passed to %s',
            $sinkType->describe(),
            $source,
            $sink
        );
    }
}
