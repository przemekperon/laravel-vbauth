<?php

namespace Pperon\Vbauth\Facades;

use Illuminate\Support\Facades\Facade;

class Vbauth extends Facade
{
    protected static function getFacadeAccessor()
    {
        return 'vbauth';
    }
}