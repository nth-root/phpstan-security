<?php

declare(strict_types=1);

namespace NthRoot\PhpstanSecurity\TaintAnalysis;

enum SinkType: string
{
    case Sql = 'sql';
    case Html = 'html';
    case Shell = 'shell';
    case FilePath = 'path';
    case FileInclusion = 'include';
    case RedirectHeader = 'redirect';
    case Unserialize = 'unserialize';
    case Callable = 'callable';
    case Eval = 'eval';

    public function identifier(): string
    {
        return 'tainted.' . $this->value;
    }

    public function describe(): string
    {
        return match ($this) {
            self::Sql => 'SQL injection',
            self::Html => 'cross-site scripting',
            self::Shell => 'command injection',
            self::FilePath => 'path traversal or SSRF',
            self::FileInclusion => 'file inclusion',
            self::RedirectHeader => 'open redirect',
            self::Unserialize => 'insecure deserialization',
            self::Callable => 'callable injection',
            self::Eval => 'eval injection',
        };
    }
}
