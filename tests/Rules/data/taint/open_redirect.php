<?php

declare(strict_types=1);

function cases(): void
{
    header('Location: ' . $_GET['url']); // unsafe
    header('location: ' . $_GET['url']); // unsafe (test that header names are case-insensitive)
    header("Location: {$_GET['url']}"); // unsafe
    header('Location: ' . $_GET['scheme'] . '://' . $_GET['host']); // unsafe
    header('Refresh: 0; url=' . $_GET['url']); // unsafe
    header(replace: true, header: 'Location: ' . $_GET['url']); // unsafe

    $prefix = 'Location: ';
    header($prefix . $_GET['url']); // unsafe
}

function safe(): void
{
    header('Location: /home', response_code: $_GET['status']); // safe (only the header is a sink)
    header('X-Request-Id: ' . $_GET['id']); // safe (not a redirect header)
}

function not_reported_yet(): void
{
    header($_GET['header']);
}

function constant_paths(): void
{
    header('Location: /dashboard?tab=' . $_GET['tab']); // safe
    header('Location:/dashboard?tab=' . $_GET['tab']); // safe
    header("Location:/dashboard?tab={$_GET['tab']}"); // safe
    header('Location: ' . '/dashboard?tab=' . $_GET['tab']); // safe

    $path = '/dashboard?tab=';
    header('Location: ' . $path . $_GET['tab']); // safe
}

function unsafe_prefixes(bool $flag): void
{
    header('Location: /' . $_GET['url']); // unsafe
    header('Location: //' . $_GET['url']); // unsafe
    header('Location: /\\' . $_GET['url']); // unsafe
    header("Location: /\t/" . $_GET['url']); // unsafe (browsers strip the tab)
    header('Location: ' . ($flag ? '/dashboard?tab=' : '/') . $_GET['url']); // unsafe
    header('Refresh: 0; url=/dashboard?tab=' . $_GET['tab']); // unsafe (only Location is handled)
}

/**
 * @param '/dashboard?tab=' $prefix
 */
function documented_prefix(string $prefix): void
{
    header('Location: ' . $prefix . $_GET['tab']); // unsafe (PHPDoc types aren't trusted)
}
