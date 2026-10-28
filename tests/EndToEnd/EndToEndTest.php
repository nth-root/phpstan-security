<?php

declare(strict_types=1);

namespace NthRoot\PhpstanSecurity\Tests\EndToEnd;

use PHPUnit\Framework\TestCase;
use Symfony\Component\Process\Process;

use function json_decode;

use const PHP_BINARY;

class EndToEndTest extends TestCase
{
    private const ROOT = __DIR__ . '/../..';

    public function testRunsInPhpstan(): void
    {
        $directory = __DIR__ . '/data';

        $this->assertSame(
            [
                [
                    'file' => $directory . '/src/Repository/UserRepository.php',
                    'line' => 15,
                    'message' => 'Possible SQL injection: tainted value from route parameter {username} is passed to Doctrine\DBAL\Connection::executeQuery()',
                    'identifier' => 'tainted.sql',
                ],
            ],
            $this->analyse($directory),
        );
    }

    /**
     * @return list<array{file: string, line: int, message: string, identifier: string}>
     */
    private function analyse(string $directory): array
    {
        $process = new Process(
            [
                PHP_BINARY,
                self::ROOT . '/vendor/bin/phpstan',
                'analyse',
                '--configuration=' . $directory . '/phpstan.neon',
                '--error-format=json',
                '--no-progress',
                '--no-interaction',
                $directory,
            ],
            self::ROOT,
        );
        $process->run();

        /** @var array{errors: list<string>, files: array<string, array{messages: list<array{message: string, line: int, identifier: string}>}>}|null $result */
        $result = json_decode($process->getOutput(), true);

        $this->assertNotEmpty($process->getOutput(), $process->getErrorOutput());

        $this->assertIsArray($result, 'PHPStan did not produce JSON output: ' . $process->getOutput());
        $this->assertSame([], $result['errors'], 'PHPStan reported general errors');

        $errors = [];

        foreach ($result['files'] as $path => $data) {
            foreach ($data['messages'] as $message) {
                $errors[] = [
                    'file' => $path,
                    'line' => $message['line'],
                    'message' => $message['message'],
                    'identifier' => $message['identifier'],
                ];
            }
        }

        return $errors;
    }
}
