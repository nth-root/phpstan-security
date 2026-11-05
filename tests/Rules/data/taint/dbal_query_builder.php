<?php

declare(strict_types=1);

use Doctrine\DBAL\Query\QueryBuilder;

function expressionCases(QueryBuilder $queryBuilder): void
{
    $queryBuilder->select($_GET['sql']); // unsafe
    $queryBuilder->select('id', $_GET['sql']); // unsafe (variadic)
    $queryBuilder->addSelect($_GET['sql']); // unsafe
    $queryBuilder->addSelect('id', $_GET['sql']); // unsafe (variadic)
    $queryBuilder->where($_GET['sql']); // unsafe
    $queryBuilder->where('id = 1', $_GET['sql']); // unsafe (variadic)
    $queryBuilder->andWhere($_GET['sql']); // unsafe
    $queryBuilder->orWhere($_GET['sql']); // unsafe
    $queryBuilder->having($_GET['sql']); // unsafe
    $queryBuilder->andHaving($_GET['sql']); // unsafe
    $queryBuilder->orHaving($_GET['sql']); // unsafe
    $queryBuilder->groupBy($_GET['sql']); // unsafe
    $queryBuilder->addGroupBy($_GET['sql']); // unsafe
    $queryBuilder->orderBy($_GET['sql']); // unsafe
    $queryBuilder->orderBy('name', $_GET['order']); // unsafe (the direction is appended as is)
    $queryBuilder->addOrderBy($_GET['sql']); // unsafe
    $queryBuilder->addOrderBy('name', $_GET['order']); // unsafe
    $queryBuilder->union($_GET['sql']); // unsafe
    $queryBuilder->addUnion($_GET['sql']); // unsafe
    $queryBuilder->with($_GET['name'], 'SELECT 1'); // unsafe
    $queryBuilder->with('cte', $_GET['sql']); // unsafe
    $queryBuilder->with('cte', 'SELECT 1', $_GET['columns']); // unsafe
}

function identifierCases(QueryBuilder $queryBuilder): void
{
    $queryBuilder->from($_GET['table']); // unsafe
    $queryBuilder->from('users', $_GET['alias']); // unsafe
    $queryBuilder->update($_GET['table']); // unsafe
    $queryBuilder->insert($_GET['table']); // unsafe
    $queryBuilder->delete($_GET['table']); // unsafe
    $queryBuilder->join('u', $_GET['table'], 'p'); // unsafe
    $queryBuilder->join('u', 'phonenumbers', $_GET['alias']); // unsafe
    $queryBuilder->join('u', 'phonenumbers', 'p', $_GET['sql']); // unsafe
    $queryBuilder->innerJoin('u', 'phonenumbers', 'p', $_GET['sql']); // unsafe
    $queryBuilder->leftJoin('u', 'phonenumbers', 'p', $_GET['sql']); // unsafe
    $queryBuilder->rightJoin('u', 'phonenumbers', 'p', $_GET['sql']); // unsafe
    $queryBuilder->set($_GET['column'], '?'); // unsafe
    $queryBuilder->set('name', $_GET['sql']); // unsafe
    $queryBuilder->setValue($_GET['column'], '?'); // unsafe
    $queryBuilder->setValue('name', $_GET['sql']); // unsafe
    $queryBuilder->values($_GET['values']); // unsafe
}

function safeCases(QueryBuilder $queryBuilder): void
{
    $queryBuilder->where('name = ?')->setParameter(0, $_GET['name']); // safe (parameters are bound)
    $queryBuilder->where('name = :name')->setParameter('name', $_GET['name']); // safe (parameters are bound)
    $queryBuilder->join($_GET['alias'], 'phonenumbers', 'p'); // safe ($fromAlias must be a known alias)
}

function whitelistCases(QueryBuilder $queryBuilder): void
{
    $sort = $_GET['sort'];

    if (!in_array($sort, ['name', 'email'], true)) {
        $sort = 'name';
    }

    $queryBuilder->orderBy($sort); // safe (whitelisted)
}
