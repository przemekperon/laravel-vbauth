<?php

namespace Pperon\Vbauth;

/**
 * VBAuth for Laravel 4
 *
 * Authentication library for vBulletin
 *
 * Based on VB_auth library for Codeigniter developed by MiklosK
 *
 * Author: Przemyslaw Peron (https://github.com/przemyslawperon)
 *
 */

use Illuminate\Container\Container;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\Cookie;


class Vbauth {
	
    protected $container;
    protected $db_prefix;
    protected $cookie_prefix;
    protected $cookie_timeout;
    protected $select_columns;
    protected $default_user = array(
        'userid' => 0,
        'username' => 'unregistered',
        'usergroupid' => 3,
        'membergroupids' => '',
        'sessionhash' => '',
        'salt' => ''
    );
    protected $info;
    protected $cookie_salt;
    protected $forum_url;

        /**
         *   Constructor;
         *   Loads configuration options and 
         *   then tries to authenticate current session against vB
         */

    public function __construct() {

            $this->db_prefix      = Config::get('vbauth::db_prefix');
            $this->cookie_salt    = Config::get('vbauth::cookie_salt');
            $this->cookie_prefix  = Config::get('vbauth::cookie_prefix');  // TODO: get this from vB db
            $this->cookie_timeout = Config::get('vbauth::cookie_timeout'); // TODO: get this from vB db
            $this->select_columns = Config::get('vbauth::select_columns');
            $this->forum_url      = Config::get('vbauth::forum_url');
            $this->groups         = Config::get('vbauth::groups');

            $this->setUserInfo($this->default_user);

            $this->authenticateSession();
        }

        /**
         * Checks cookies for a valid session hash, and queries session table to
         * see if user is already logged in.  Sets $info value to queried result
         *
         * @return	boolean		true = the user is logged in
         */
        public function authenticateSession()
        {
            // check bbuser cookies (stored when 'remember me' checked)
            $userid = Cookie::get($this->cookie_prefix .'userid');
            $password = Cookie::get($this->cookie_prefix .'password');

            //check sessionhash
            $vb_sessionhash =  Cookie::get($this->cookie_prefix.'sessionhash');

            if ((!empty($userid) && !empty($password))) {

                // we have a remembered user
                $user = $this->isValidCookieUser($userid, $password);

                if (!empty($user)) {

                    // create user session
                    $vb_sessionhash = $this->createSession($userid);
                } else {

                    // invalid userid and password in cookie: authentication failed, force login
                    return false;
                }
            }

            // Logged in vB via session
            if (!empty($vb_sessionhash)) {
				$session = DB::table($this->dbprefix.'session')
				->where('sessionhash', $vb_sessionhash)
				->where('idhash', $this->fetchIdHash())
				->where('lastactivity', time() - $this->cookie_timeout)
				->get()->toArray();

                if (empty($session)) {
                    return false;
                }

                if (is_array($session[0]) and $session[0]['host'] == substr(Request::server('REMOTE_ADDR'), 0, 15)) {
                    $userinfo = DB::table($this->dbprefix.'user')
                    ->select(implode(', ', $this->select_columns))
                    ->where('userid', $session[0]['userid'])
                    ->get()->toArray();

                    if (empty($userinfo)) {
                        return false;
                    }

                    $userinfo[0]['sessionhash'] = $session[0]['sessionhash'];

                    // cool, session is authenticated

                    $this->setUserInfo($userinfo[0]);

                    // now let's inform vB what this user is just doing

                    $update_session = array(
                    'lastactivity' => time(),
                    'location'     => Request::server('REQUEST_URI'),
                    );

					DB::table($this->dbprefix.'session')
					->where('sessionhash', $session[0]['sessionhash'])
					->update($update_session);

                    return true;
                }
            }

            return false;
        }

        /**
         * Checks to see if $userid and hashed $password are valid credentials.
         *
         * @param   int     $userid
         * @param   string  $password
         * @return	integer	0 = false; X > 1 = Userid
         */
        public function isValidCookieUser($userid, $password)
        {
			$user = DB::table($this->dbprefix.'user')
			->select('username')
			->where('userid', $userid)
			->where(DB::raw("md5(concat(password,'".$this->cookie_salt."')) = '$password'"))
			->get()->toArray();
            if (empty($user)) {
                return false;
            }

            return intval($userid);
        }

        /**
         * Checks to see if $username and $password are valid credentials.
         *
         * @param   string     $username
         * @param   string     $password
         * @return	integer	   0 = false; X > 1 = Userid
         */
        public function isValidLogin($username, $password)
        {
			$user = DB::table($this->dbprefix.'user')
			->select('userid')
			->where('username', $username)
			->where(DB::raw("password = md5(concat(md5('".$password."'), salt))"))
			->get()->toArray();

            if (empty($user)) {
                return false;
            }

            return intval($user[0]['userid']);
        }

        /**
         *	Sets the cookies for a cookie user.  Call on login process ('remember me' option)
         *	Sets cookie timeout to 1 year from now
         *
         *  @param   int     $userid
         *  @param   string  $password
         *	@return  null;
         */
        public function createCookieUser($userid, $password)
        {
			Cookie::put($this->cookie_prefix.'userid', $userid, time() + 31536000);
			Cookie::put($this->cookie_prefix.'password', md5($password . $this->cookie_salt), time() + 31536000);
        }

        /**
         * Creates a session for $userid (logs them into vBulletin) by creating
         * both a cookie and an entry in the session table.
         *
         * @param   int     $userid         
         * @param	integer		Userid to log in
         */
        public function createSession($userid)
        {
            $hash = md5(microtime().$userid.Request::server('REMOTE_ADDR'));

            $timeout = time() + $this->cookie_timeout;

            Cookie::put($this->cookie_prefix . 'sessionhash', $hash, $timeout);

            $session = array(
            'userid'       => $userid,
            'sessionhash'  => $hash,
            'host'         => Request::server('REMOTE_ADDR'),
            'idhash'       => $this->fetchIdHash(),
            'lastactivity' => time(),
            'location'     => Request::server('REQUEST_URI'),
            'useragent'    => Request::server('HTTP_USER_AGENT'),
            'loggedin'     => 1
            );
			DB::table($this->dbprefix.'session')
			->insert($session);

            return $hash;
        }

        /**
         * Deletes the users session by expiring the cookie and removing the
         * entry from the session table.
         */
        public function deleteSession()
        {
            Cookie::put($this->cookie_prefix.'sessionhash', '', time() - 3600);
            Cookie::put($this->cookie_prefix.'userid', '', time() - 3600);
            Cookie::put($this->cookie_prefix.'password', '', time() - 3600);
            
            DB::table($this->dbprefix.'session')
            ->where('sessionhash', $this->info['sessionhash'])
            ->delete();
        }

        /**
         * Sets the userinfo array to be used
         * @param	array      $userinfo
         */
        public function setUserInfo($userinfo)
        {
            $this->info = $userinfo;
        }

        /**
         * Checks to see if the current user is a member of $group ('admin', for ex)
         * Name to ID mapping is in config file.
         *
         * @param	string		Group varname
         * @return	boolean		True = in group; false not in group
         */
        public function is($group)
        {
            if (empty($this->groups[$group])) {
                return false;
            }

            static $my_groups;

            if (!is_array($my_groups)) {
                $my_groups = array($this->info['usergroupid']);

                foreach (explode(',', $this->info['membergroupids']) as $id) {
                    if ($id) {
                        $my_groups[] = intval($id);
                    }
                }
            }

            return (bool) count(array_intersect($my_groups, $this->groups[$group]));

        }

        /**
         * Fetches the "id_hash" (vbulletin; see class_core.php)
         *
         * @return	string		Hashed user agent + shortened IP address
         */
        public function fetchIdHash()
        {
            return md5(Request::server('HTTP_USER_AGENT') . $this->fetchSubstrIp($this->fetchAltIp()));
        }

        /**
         * Fetches the "substr_ip" (vbulletin; see class_core.php)
         *
         * @return	string		IP address
         */
        public function fetchSubstrIp($ip, $length = null)
        {
            if ($length === null OR $length > 3) {
                $length = 1;
            }

            return implode('.', array_slice(explode('.', $ip), 0, 4 - $length));
        }

        /**
         * Fetches the users "alt_ip" (vbulletin; see class_core.php)
         *
         * @return	string		IP address
         */
        public function fetchAltIp()
        {
            $alt_ip = Request::server('REMOTE_ADDR');

            if (Request::server('HTTP_CLIENT_IP') !== null) {
                $alt_ip = Request::server('HTTP_CLIENT_IP');
            } elseif (Request::server('HTTP_X_FORWARDED_FOR') !== null AND preg_match_all('#\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}#s', Request::server('HTTP_X_FORWARDED_FOR'), $matches)) {
                // make sure we dont pick up an internal IP defined by RFC1918
                foreach ($matches[0] AS $ip) {
                    if (!preg_match("#^(10|172\.16|192\.168)\.#", $ip)) {
                        $alt_ip = $ip;
                        break;
                    }
                }
            } elseif (Request::server('HTTP_FROM') !== null ) {
                $alt_ip = Request::server('HTTP_FROM');
            }

            return $alt_ip;
        }

        /**
         * Checks if the current user is logged in to vB
         *
         * @return	bool    true if valid vb user, false if anonym visitor
         */
        public function isLoggedIn()
        {
            return (isset($this->info['userid'])  && !empty($this->info['userid']));
        }

        /**
         * Checks if the current user is a vB administrator
         *
         * @return	bool
         */

        public function isAdmin()
        {
            return (isset($this->info['userid'])  && !empty($this->info['userid']) && $this->is('admin'));
        }
        /**
         * Compose a logout url for remote logout links
         *
         * @return	string
         */
        public function logoutUrl()
        {
            $securitytoken_raw = sha1($this->info['userid'] . sha1($this->info['salt']) . sha1($this->cookie_salt));
            $securitytoken = time() . '-' . sha1(time() . $securitytoken_raw);

            $logoutUrl    = $this->forum_url.'login.php?do=logout&logouthash='.$securitytoken;

            return $logoutUrl;
        }
        /**
         * 	PHP 5 __GET()
         *
         */
     public function __get($var)
     {
         return $this->info["$var"];
     }

     public function setContainer(Container $container)
     {
         $this->container = $container;
     }
}
