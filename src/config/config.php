<?php

/*
 * cookiesalt - you can get this in the Vbulletin installation:
 *              includes/functions.php (line 34.)
 *              Example:              
 *              define('COOKIE_SALT', 'ABCdefghjkklmno123456790');
 *              ABCdefghjkklmno123456790 is the cookiesalt
 */

return array(
	'dbprefix' => 'vb_',
	'cookiesalt' => 'ABCdefghjkklmno123456790',
	'cookieprefix' => 'bb_',
	'cookietimeout' => 3600,
	'cookiedomain' => 'domain.com',
	'forum_url' => 'http://www.domain.com/forum/',
	'selectcolumns' => array(
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
