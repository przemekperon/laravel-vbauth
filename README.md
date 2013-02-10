Authentication for [VBulletin](http://www.vbulletin.com) users in [Laravel 4](http://laravel.com/). Tested with VBulletin 4.x.

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
'providers' => array(
		...
		...
		'Pperon\Vbauth\VbauthServiceProvider',
),
```

In order to use shorter class alias add it to alias sections in app/config/app.php:

```php
'aliases' => array(
		...
		...
		'Vbauth'		  => 'Pperon\Vbauth\Vbauth',
),
```

Configuration
=============

Default configuration file is located in vendor/pperon/vbauth/src/config/config.php but you should overwrite it with `app/config/packages/pperon/vbauth/config.php` file.


Usage
=====

Example usage in a controller:

```php
$vbauth = new Vbauth();
if($vbauth->isAdmin()){
	// Show administrator page
	View::make('admin.index');
} elseif ($vbauth->isLoggedin()) {
	// Show user page
	View::make('user.index');	
} else {
	// Show guest page
	View::make('guest.index');
}
```

###Vbulletin User Variables

You may access user information directly by calling $vbauth->fieldname. Fields are defined in config.php (select_columns).

Example:
```php
$vbauth = new Vbauth();
if($vbauth->isLoggedin()) {
    $user_id = $vbauth->userid;
    $username = $vbauth->username;
    $email = $vbauth->email;
}

```

###isLoggedIn()

Checks for VBulletin user cookie and returns:

TRUE - user is logged in,
FALSE - there is no vbulletin cookie (user not logged in)


###isAdmin()

Checks whether the user belongs to Admin usergroup. Usually this means the user belongs to usergroup with id = 6 but you can modify this in config.php file by changing admin group ids.

TRUE - user belongs to admin usergroup
FALSE - user doesn't belong to admin usergroup

###is()

Checks whether the user belongs to specific usergroup. Default available groups: `admin, moderator, user, banned, guest`.  You can add more in config.php.

TRUE - user belongs to specific group

Example:
```php
$vbauth = new Vbauth();
if($vbauth->is('moderator')) {
    View::make('moderator.panel');
}
```

###logoutUrl()

Returns URL to logout script in Vbulletin installation.

Example:
```php
$vbauth = new Vbauth();
Redirect::to($vbauth->logoutURL());
```