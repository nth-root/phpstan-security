<?php

declare(strict_types=1);

use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\Filesystem\Filesystem;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

function filesystem(Filesystem $filesystem): void
{
    $path = '/var/uploads/' . $_GET['file'];

    $filesystem->readFile($path); // unsafe
    $filesystem->dumpFile($path, 'content'); // unsafe
    $filesystem->appendToFile($path, 'content'); // unsafe
    $filesystem->remove($path); // unsafe
    $filesystem->copy($path, '/tmp/copy'); // unsafe
    $filesystem->copy('/tmp/original', $path); // unsafe
    $filesystem->rename('/tmp/original', $path); // unsafe
    $filesystem->mkdir($path); // unsafe
    $filesystem->touch($path); // unsafe
    $filesystem->chmod($path, 0o644); // unsafe
    $filesystem->symlink($path, '/var/www/link'); // unsafe
    $filesystem->dumpFile('/var/log/app.log', $_GET['message']); // safe (only the path is a sink)
    $filesystem->exists($path); // safe (not a sink)
}

class DownloadController extends AbstractController
{
    public function download(Request $request): Response
    {
        return $this->file('/var/uploads/' . $request->query->get('name')); // unsafe
    }

    public function safe(Request $request): Response
    {
        return $this->file('/var/uploads/report.pdf', $request->query->get('name')); // safe (only the file is a sink)
    }
}
