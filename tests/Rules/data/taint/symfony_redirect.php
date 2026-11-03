<?php

declare(strict_types=1);

use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

class RedirectController extends AbstractController
{
    public function unsafe(Request $request): Response
    {
        return $this->redirect($request->query->get('next')); // unsafe
    }

    public function safe(Request $request): Response
    {
        return $this->redirect('/dashboard', $request->query->get('status')); // safe (only the URL is a sink)
    }
}
