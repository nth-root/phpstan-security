<?php

declare(strict_types=1);

namespace NthRoot\PhpstanSecurity\TaintAnalysis;

use PHPStan\Analyser\Scope;

final readonly class FunctionKey
{
    /**
     * @return string "App\Controller\UserController::show", "App\helper", or file name for code outside of any function
     */
    public static function of(Scope $scope): string
    {
        $function = $scope->getFunction();

        if (!$function) {
            return $scope->getFile();
        }

        $class = $scope->getClassReflection();

        if ($class === null) {
            return $function->getName();
        }

        return $class->getName() . '::' . $function->getName();
    }
}
