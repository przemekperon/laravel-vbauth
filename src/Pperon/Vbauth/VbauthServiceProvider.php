<?php namespace Pperon\Vbauth;

use Illuminate\Support\ServiceProvider;

class VbauthServiceProvider extends ServiceProvider
{
    /**
     * Indicates if loading of the provider is deferred.
     *
     * @var bool
     */
    protected $defer = false;

    /**
     * Bootstrap the application events.
     *
     * @return void
     */
    public function boot()
    {
        $this->package('pperon/vbauth');
    }

    /**
     * Register the service provider.
     *
     * @return void
     */
    public function register()
    {
        $this->app['config']->package('pperon/vbauth', __DIR__.'/../../config', 'pperon/vbauth');

        $this->app['vbauth'] = $this->app->share(function ($app) {
            return new Vbauth;
        });
    }

    /**
     * Get the services provided by the provider.
     *
     * @return array
     */
    public function provides()
    {
        return array('vbauth');
    }

}
