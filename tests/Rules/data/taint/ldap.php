<?php

declare(strict_types=1);

use Symfony\Component\Ldap\LdapInterface;

function cases($connection, LdapInterface $ldap): void
{
    ldap_search($connection, 'dc=example,dc=com', '(uid=' . $_GET['user'] . ')'); // unsafe (filter)
    ldap_list($connection, 'ou=' . $_GET['unit'] . ',dc=example,dc=com', '(objectClass=*)'); // unsafe (base)
    ldap_read($connection, $_GET['dn'], '(objectClass=*)'); // unsafe
    $ldap->query('dc=example,dc=com', '(uid=' . $_GET['user'] . ')'); // unsafe (query)
    $ldap->query('ou=' . $_GET['unit'] . ',dc=example,dc=com', '(objectClass=*)'); // unsafe (dn)
    echo ldap_escape($_GET['user']); // unsafe (escaped for LDAP, not HTML)
}

function safe($connection, LdapInterface $ldap): void
{
    $user = ldap_escape($_GET['user'], '', LDAP_ESCAPE_FILTER);
    ldap_search($connection, 'dc=example,dc=com', '(uid=' . $user . ')'); // safe (escaped)
    ldap_search($connection, 'dc=example,dc=com', '(uid=jdoe)', $_GET['attributes']); // safe (only base and filter)
    $ldap->query('dc=example,dc=com', '(uid=jdoe)', $_GET['options']); // safe (only dn and query)
}
