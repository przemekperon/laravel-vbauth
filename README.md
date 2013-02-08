Authorization for [VBulletin](http://www.vbulletin.com) users in [Laravel 4](http://laravel.com/). Tested with VBulletin 4.x

Installation
============
 
Add `pperon/vbauth` as a requirement to composer.json:

```javascript
{
    "require": {
        "pperon/vbauth": "1.*"
    }
}
```

Update your packages with `composer update` or install with `composer install`.

Once Composer has installed or updated your packages you need to register Vbauth with Laravel itself. Open app/config/app.php and find the providers key towards the bottom and add:

```php
'Pperon\VbauthServiceProvider'
```

Configuration
=============

Default configuration file is in vendor/pperon/vbauth/src/config/config.php but you can overwrite it by creating `app/config/packages/pperon/vbauth/config.php` file.

You can use Artisan to publish a configuration file by running the following command:

```
$ php artisan config:publish pperon/vbauth
```

Usage
=====

```php
$vbauth = new Vbauth();
$is_admin = $vbAuth->isAdmin();
$is_logged_in = $vbAuth->isLoggedIn();
```
