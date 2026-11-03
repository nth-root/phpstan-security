<?php

declare(strict_types=1);

use Symfony\Component\HttpFoundation\BinaryFileResponse;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Response;

class PlainResponse extends Response
{
}

class LoginRedirectResponse extends RedirectResponse
{
    public function __construct(string $target)
    {
        parent::__construct($target); // unsafe (called with $_GET)
    }
}

class EscapedResponse extends Response
{
    public function __construct(string $content)
    {
        parent::__construct(htmlspecialchars($content)); // safe (escaped)
    }
}

function cases(): void
{
    new Response('<p>Hello ' . $_GET['name'] . '</p>'); // unsafe
    new Response(content: $_GET['html']); // unsafe
    new RedirectResponse($_GET['next']); // unsafe
    new BinaryFileResponse('/var/uploads/' . $_GET['file']); // unsafe
    new PlainResponse($_GET['html']); // unsafe (inherits Response's constructor)
    new LoginRedirectResponse($_GET['next']);
}

function safe(): void
{
    new Response('Hello', $_GET['status']); // safe (only the content is a sink)
    new RedirectResponse('/home', $_GET['status']); // safe (only the URL is a sink)
    new JsonResponse($_GET['data']); // safe (JSON, not HTML)
    new EscapedResponse($_GET['html']); // safe (declares its own constructor, which escapes)
}
