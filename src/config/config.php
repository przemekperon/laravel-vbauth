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

return array(
	'db_prefix' => 'vb_',
	'cookie_salt' => 'ABCdefghjkklmno123456790',
	'cookie_prefix' => 'bb_',
	'cookie_timeout' => 3600,
	'cookie_domain' => 'domain.com',
	'forum_url' => 'http://www.domain.com/forum/',
	
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
