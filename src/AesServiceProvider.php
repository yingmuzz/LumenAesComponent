<?php
/**
 * AES 加密解密服务初始化。
 *
 * @author    YingMuzZ <huadyingmu@gmail.com>
 * @copyright © 2020 YingMuzZ
 * @version   v1.0
 */

namespace YingMuzZ\LumenAesComponent;

use Illuminate\Support\Facades\Config;
use Illuminate\Support\ServiceProvider;

class OpensslAesServiceProvider extends ServiceProvider
{
    public function register()
    {
        $this->app->singleton('lumenaes', function ($app) {
            $s_path = parse_url($_SERVER['REQUEST_URI'])['path'];
            $a_urls = explode('/', $s_path);
            $s_version = (isset($a_urls[1]) && $a_urls[1] != '') ? $a_urls[1] : '';
            $a_versions = Config::get('lumenaes');
            if ('' == $s_version || !count($a_versions) || !isset($a_versions[$s_version])) {
                throw new \Exception('路由异常！~');
            }

            return new LumenAesTool($s_version);
        });
    }

    public function boot()
    {
    }
}
