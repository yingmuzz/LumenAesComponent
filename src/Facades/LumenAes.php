<?php
/**
 * LumenAesComponent Facade。
 *
 * @author    YingMuzZ <huadyingmu@gmail.com>
 * @copyright © 2020 YingMuzZ
 * @version   v1.0
 */

namespace YingMuzZ\LumenAesComponent\Facades;

use Illuminate\Support\Facades\Facade;

class LumenAes extends Facade
{
    protected static function getFacadeAccessor()
    {
        return 'lumenaes';
    }
}
