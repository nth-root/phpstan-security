<?php

declare(strict_types=1);

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsToMany;
use Illuminate\Database\Eloquent\Relations\HasMany;

class Item extends Model
{
    /**
     * @return HasMany<Item, $this>
     */
    public function children(): HasMany
    {
        return $this->hasMany(Item::class, 'parent_id');
    }

    /**
     * @return BelongsToMany<Item, $this>
     */
    public function related(): BelongsToMany
    {
        return $this->belongsToMany(Item::class);
    }
}

function cases(Item $item): void
{
    $item->children()->whereRaw($_GET['sql']); // unsafe
    $item->related()->orderByRaw($_GET['sort']); // unsafe
}

function safe(Item $item): void
{
    $item->children()->whereRaw('id = ?', [$_GET['id']]); // safe (bindings)
}
