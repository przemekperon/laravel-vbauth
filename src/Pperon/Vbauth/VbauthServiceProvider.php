<?php namespace Pperon\Vbauth;

use Illuminate\Support\ServiceProvider;

class VbauthServiceProvider extends ServiceProvider
{
    /**
     * Indicates if loading of the provider is deferred.
     *
     * @var bool
     */
    protected $defer = true;

    /**
     * Bootstrap the application events.
     *
     * @return void
     */
    public function boot()
    {
        $this->publishes([
            __DIR__ . '/path/to/config/vbauth.php' => config_path('vbauth.php'),
        ]);
    }

    /**
     * Register the service provider.
     *
     * @return void
     */
    public function register()
    {
        $this->app['vbauth'] = $this->app->share(function ($app) {
            return new Vbauth();
        });
    }

    /**
     * Get the services provided by the provider.
     *
     * @return array
     */
    public function provides()
    {
        return ['vbauth'];
    }

}
