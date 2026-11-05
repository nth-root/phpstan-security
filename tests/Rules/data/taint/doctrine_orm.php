<?php

declare(strict_types=1);

use Doctrine\ORM\EntityManagerInterface;
use Doctrine\ORM\EntityRepository;
use Doctrine\ORM\NativeQuery;
use Doctrine\ORM\Query;
use Doctrine\ORM\Query\ResultSetMapping;
use Doctrine\ORM\QueryBuilder;

class OrmUserRepository extends EntityRepository {}

function queryCases(EntityManagerInterface $entityManager, ResultSetMapping $rsm, Query $query, NativeQuery $nativeQuery): void
{
    $entityManager->createQuery('SELECT u FROM User u WHERE u.name = \'' . $_GET['name'] . '\''); // unsafe
    $entityManager->createNativeQuery($_GET['sql'], $rsm); // unsafe
    $query->setDQL($_GET['dql']); // unsafe
    $nativeQuery->setSQL($_GET['sql']); // unsafe
}

function repositoryCases(OrmUserRepository $repository): void
{
    $repository->createQueryBuilder($_GET['alias']); // unsafe
    $repository->createQueryBuilder('u', $_GET['field']); // unsafe
}

function expressionCases(QueryBuilder $queryBuilder): void
{
    $queryBuilder->select($_GET['dql']); // unsafe
    $queryBuilder->select('u', $_GET['dql']); // unsafe (variadic)
    $queryBuilder->addSelect($_GET['dql']); // unsafe
    $queryBuilder->where($_GET['dql']); // unsafe
    $queryBuilder->where('u.id = 1', $_GET['dql']); // unsafe (variadic)
    $queryBuilder->andWhere($_GET['dql']); // unsafe
    $queryBuilder->orWhere($_GET['dql']); // unsafe
    $queryBuilder->having($_GET['dql']); // unsafe
    $queryBuilder->andHaving($_GET['dql']); // unsafe
    $queryBuilder->orHaving($_GET['dql']); // unsafe
    $queryBuilder->groupBy($_GET['dql']); // unsafe
    $queryBuilder->addGroupBy($_GET['dql']); // unsafe
    $queryBuilder->orderBy($_GET['dql']); // unsafe
    $queryBuilder->orderBy('u.name', $_GET['order']); // unsafe (only validated since ORM 3.7)
    $queryBuilder->addOrderBy($_GET['dql']); // unsafe
    $queryBuilder->addOrderBy('u.name', $_GET['order']); // unsafe
    $queryBuilder->add('where', $_GET['dql']); // unsafe
}

function identifierCases(QueryBuilder $queryBuilder): void
{
    $queryBuilder->from($_GET['entity'], 'u'); // unsafe
    $queryBuilder->from('User', $_GET['alias']); // unsafe
    $queryBuilder->from('User', 'u', $_GET['field']); // unsafe
    $queryBuilder->update($_GET['entity']); // unsafe
    $queryBuilder->update('User', $_GET['alias']); // unsafe
    $queryBuilder->delete($_GET['entity']); // unsafe
    $queryBuilder->delete('User', $_GET['alias']); // unsafe
    $queryBuilder->join($_GET['association'], 'p'); // unsafe
    $queryBuilder->join('u.phonenumbers', $_GET['alias']); // unsafe
    $queryBuilder->join('u.phonenumbers', 'p', $_GET['type'], 'p.active = 1'); // unsafe
    $queryBuilder->join('u.phonenumbers', 'p', 'WITH', $_GET['dql']); // unsafe
    $queryBuilder->join('u.phonenumbers', 'p', null, null, $_GET['field']); // unsafe
    $queryBuilder->innerJoin('u.phonenumbers', 'p', 'WITH', $_GET['dql']); // unsafe
    $queryBuilder->leftJoin('u.phonenumbers', 'p', 'WITH', $_GET['dql']); // unsafe
    $queryBuilder->indexBy('u', $_GET['field']); // unsafe
    $queryBuilder->set($_GET['field'], '?1'); // unsafe
    $queryBuilder->set('u.name', $_GET['dql']); // unsafe
}

function safeCases(QueryBuilder $queryBuilder): void
{
    $queryBuilder->where('u.name = :name')->setParameter('name', $_GET['name']); // safe (parameters are bound)
    $queryBuilder->indexBy($_GET['alias'], 'id'); // safe ($alias must be a root alias)
}
