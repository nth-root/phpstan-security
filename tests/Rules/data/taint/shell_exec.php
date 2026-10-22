<?php

declare(strict_types=1);

function direct(): void
{
    `ls {$_GET['dir']}`; // unsafe
}

function withVariable(): void
{
    $dir = $_GET['dir'];
    `ls $dir`; // unsafe
}

function safe(): void
{
    `ls`;
}
