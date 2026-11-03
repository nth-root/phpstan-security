<?php

declare(strict_types=1);

use Symfony\Component\DomCrawler\Crawler;

function cases(DOMXPath $xpath, SimpleXMLElement $xml, Crawler $crawler): void
{
    $xpath->query("//user[name='" . $_GET['name'] . "']"); // unsafe
    $xpath->evaluate('count(//user[@role="' . $_GET['role'] . '"])'); // unsafe
    $xml->xpath("//user[name='{$_GET['name']}']"); // unsafe
    $crawler->filterXPath("//a[@class='" . $_GET['class'] . "']"); // unsafe
    $crawler->evaluate('count(//a[@rel="' . $_GET['rel'] . '"])'); // unsafe
}

function safe(DOMXPath $xpath, SimpleXMLElement $xml, Crawler $crawler): void
{
    $xpath->query('//user');
    $xpath->query('//user', null, $_GET['ns']); // safe (only the expression is a sink)
    $xml->xpath('//user');
    $crawler->filterXPath('//a');
    $crawler->filter('a.' . $_GET['class']); // safe (a CSS selector, not XPath)
}
