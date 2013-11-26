<?php

/**
 * cookie_salt - you can get this from the Vbulletin installation:
 *               includes/functions.php (line 34.)
 *               Example:              
 *               define('COOKIE_SALT', 'ABCdefghjkklmno123456790');
 *               ABCdefghjkklmno123456790 is the cookiesalt
 *
 *			 	 IMPORTANT!!! without cookie_salt it's impossible to 
 *               decode vbulletin cookies
 */
/**
 * db_connection - if the vbulletin database is in different database than
 *                 your Laravel setup please change it to the proper connection
 *                 name. Connection should be configured in app/config/database.php
 *                 Example:
 *                'connections' => array(
 *                 ....
 *                    'vbconn' => array(
 *                      'driver'    => 'mysql',
 *                      'host'      => 'localhost',
 *                      'database'  => 'vb_forum',
 *                      'username'  => 'vb_user',
 *                      'password'  => 'pass123',
 *                      'charset'   => 'utf8',
 *                      'collation' => 'utf8_unicode_ci',
 *                      'prefix'    => '',
 *                    ),
 *
 *                in /config/packages/pperon/vbauth/config.php set:
 *                ....
 *                     'db_connection' => 'vbconn',
 *                ....
 */
return array(
    'db_prefix' => 'vb_',
    'cookie_salt' => 'ABCdefghjkklmno123456790',
    'cookie_prefix' => 'bb_',
    'cookie_timeout' => 3600,
    'cookie_domain' => 'domain.com',
    'forum_url' => 'http://www.domain.com/forum/',
    'db_connection' => 'mysql',
    'select_columns' => array(
        'userid',
        'username',
        'usergroupid',
        'membergroupids',
        'email',
        'salt',
    ),

    'groups' => array(
        'admin'     	=> array(6),
        'moderator' 	=> array(5, 7),
        'user'      	=> array(2),
        'banned'    	=> array(8),
        'guest'     	=> array(3),
    ),
);
