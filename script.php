<?php

session_start();

$name 		 = $_POST['user_name'];
$destination = 'CLIENTS/'.$name;

if (file_exists($destination)) {
	echo("<script>location = 'error1.html';</script>");
	exit;
}


echo("<script>location = 'payment.html';</script>");

$name 		= $_POST['user_name'];
$password 	= $_POST['user_password'];

$fname	= $_POST['firstname'];
$sname	= $_POST['surname'];
$email	= $_POST['email'];
$site	= $_POST['site'];
$host = 'localhost';
$serverurl = 'www.cakemanage.com';

//include('loading.html');

// Check DATABASE for existing user!!! and complete information at the end.
// Also PUT information from login process and "Please wait..." note
// Functions

function getCryptedPasswordOS($pass) { return sha1($pass.sha1($pass));};
function make_data_str  ($str){ return 's:'.strlen($str).':"'.$str.'";';}
function make_data_email($email){ return make_data_str(str_replace('@','%40',$email));}
function getSalt($encryption = 'md5-hex', $seed = '', $plaintext = ''){
	switch ($encryption){
		case 'crypt' :
		case 'crypt-des' :
			if ($seed) 	{ return substr(preg_replace('|^{crypt}|i', '', $seed), 0, 2);}
			else 		{ return substr(md5(mt_rand()), 0, 2); }
			break;
		case 'crypt-md5' :
			if ($seed) 	{ return substr(preg_replace('|^{crypt}|i', '', $seed), 0, 12);}
			else 		{ return '$1$'.substr(md5(mt_rand()), 0, 8).'$'; }
			break;

		case 'crypt-blowfish' :
			if ($seed) 	{ return substr(preg_replace('|^{crypt}|i', '', $seed), 0, 16); }
			else 		{ return '$2$'.substr(md5(mt_rand()), 0, 12).'$';}
			break;

		case 'ssha' :
			if ($seed)  { return substr(preg_replace('|^{SSHA}|', '', $seed), -20); }
			else 		{ return mhash_keygen_s2k(MHASH_SHA1, $plaintext, substr(pack('h*', md5(mt_rand())), 0, 8), 4);	}
			break;

		case 'smd5' :
			if ($seed) 	{ return substr(preg_replace('|^{SMD5}|', '', $seed), -16); }
			else 		{ return mhash_keygen_s2k(MHASH_MD5, $plaintext, substr(pack('h*', md5(mt_rand())), 0, 8), 4); }
			break;

		case 'aprmd5' :
			/* 64 characters that are valid for APRMD5 passwords. */
			$APRMD5 = './0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';

			if ($seed) {return substr(preg_replace('/^\$apr1\$(.{8}).*/', '\\1', $seed), 0, 8); }
			else {
				$salt = '';
				for ($i = 0; $i < 8; $i ++) {
					$salt .= $APRMD5 { rand(0, 63) };
				}
				return $salt;
			}
			break;
		default :
			$salt = '';
			if ($seed) { $salt = $seed;	}
			return $salt;
			break;
	}
}
function getCryptedPassword($plaintext, $salt = '', $encryption = 'md5-hex', $show_encrypt = false){
	$salt = getSalt($encryption, $salt, $plaintext);
	switch ($encryption){
		case 'plain' 	: return $plaintext;
		case 'sha' 		:
			$encrypted = base64_encode(mhash(MHASH_SHA1, $plaintext));
			return ($show_encrypt) ? '{SHA}'.$encrypted : $encrypted;
		case 'crypt' :
		case 'crypt-des' :
		case 'crypt-md5' :
		case 'crypt-blowfish' : 	return ($show_encrypt ? '{crypt}' : '').crypt($plaintext, $salt);
		case 'md5-base64' :
			$encrypted = base64_encode(mhash(MHASH_MD5, $plaintext));
			return ($show_encrypt) ? '{MD5}'.$encrypted : $encrypted;
		case 'ssha' :
			$encrypted = base64_encode(mhash(MHASH_SHA1, $plaintext.$salt).$salt);
			return ($show_encrypt) ? '{SSHA}'.$encrypted : $encrypted;
		case 'smd5' :
			$encrypted = base64_encode(mhash(MHASH_MD5, $plaintext.$salt).$salt);
			return ($show_encrypt) ? '{SMD5}'.$encrypted : $encrypted;
		case 'aprmd5' :
			$length = strlen($plaintext);
			$context = $plaintext.'$apr1$'.$salt;
			$binary = JUserHelper::_bin(md5($plaintext.$salt.$plaintext));

			for ($i = $length; $i > 0; $i -= 16) {
				$context .= substr($binary, 0, ($i > 16 ? 16 : $i));
			}
			for ($i = $length; $i > 0; $i >>= 1) {
				$context .= ($i & 1) ? chr(0) : $plaintext[0];
			}

			$binary = JUserHelper::_bin(md5($context));
			for ($i = 0; $i < 1000; $i ++) {
				$new = ($i & 1) ? $plaintext : substr($binary, 0, 16);
				if ($i % 3) {
					$new .= $salt;
				}
				if ($i % 7) {
					$new .= $plaintext;
				}
				$new .= ($i & 1) ? substr($binary, 0, 16) : $plaintext;
				$binary = JUserHelper::_bin(md5($new));
			}

			$p = array ();
			for ($i = 0; $i < 5; $i ++) {
				$k = $i +6;
				$j = $i +12;
				if ($j == 16) { $j = 5;}
				$p[] = JUserHelper::_toAPRMD5((ord($binary[$i]) << 16) | (ord($binary[$k]) << 8) | (ord($binary[$j])), 5);
			}

			return '$apr1$'.$salt.'$'.implode('', $p).JUserHelper::_toAPRMD5(ord($binary[11]), 3);

		case 'md5-hex' :
		default :
			$encrypted = ($salt) ? md5($plaintext.$salt) : md5($plaintext);
			return ($show_encrypt) ? '{MD5}'.$encrypted : $encrypted;
	}
}
function genRandomPassword($length = 8)	{
	$salt = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
	$len = strlen($salt);
	$makepass = '';
	$stat = @stat(__FILE__);
	if(empty($stat) || !is_array($stat)) $stat = array(php_uname());

	mt_srand(crc32(microtime() . implode('|', $stat)));
	for ($i = 0; $i < $length; $i ++) {
		$makepass .= $salt[mt_rand(0, $len -1)];
	}
	return $makepass;
}
function random($num){
	$ret ='';
	for ($i=0; $i<$num; $i++) {
		$d=rand(1,30)%2;
		$ret = $ret.($d ? chr(rand(65,90)) : chr(rand(48,57)));
	}
	return $ret;
}
function random_numeric($num){
	$ret ='';
	for ($i=0; $i<$num; $i++) $ret = $ret.$d=rand(0,9);
	return $ret;
}

// Procedures

$destination = 'CLIENTS/'.$name;
if (!file_exists($destination)) {
	$link = mysql_connect("localhost","root","ENTER_PASSWORD_HERE");

	if($site=='JOOMLA'){
		// Script for Joomla CMS
		$source	= 'ExampleCMS';
		$destination  = 'CLIENTS/'.$name;
		shell_exec("mkdir $destination");
		shell_exec("cp -apR $source/* $destination");	//copy_directory( $source, $destination );
		echo "JCMS Files copy: ok".'<br>';

		$configincphp = $destination.'/configuration.php';
		$tmp1 		  = $destination.'/configuration.php.tmp1';
		$tmp2         = $destination.'/configuration.php.tmp2';
		$tmp3         = $destination.'/configuration.php.tmp3';

	    $unique = random(16);
		shell_exec("cat $configincphp | sed s/@@VARIABLE@@/$name/mg > $tmp1");
		shell_exec("cat $tmp1 | sed s/@@PASSWORD@@/$password/mg > $tmp2");
		shell_exec("cat $tmp2 | sed s/@@UNIQUE@@/$unique/mg > $tmp3");
		shell_exec("mv  $tmp3 $configincphp");
		echo "JCMS Config File: ok".'<br>';

		$new_db = "CakeCMSdb_".$name;
		mysql_query("create database $new_db"); //GRANT USAGE ON * . * TO  'bla'@'localhost' IDENTIFIED BY  '***' WITH MAX_QUERIES_PER_HOUR 0 MAX_CONNECTIONS_PER_HOUR 0 MAX_UPDATES_PER_HOUR 0 MAX_USER_CONNECTIONS 0 ;

		$dbpassw = $password.'_aNqHzQL9';
		$query = "grant all on $new_db.* to '$name'@'$host' identified by '$dbpassw';";// source '$sqlscript'";
		mysql_query($query);

		$sqlscript = 'joomla_init_database.sql';
		passthru("nohup mysql -u root -p'ENTER_PASSWORD_HERE' $new_db < $sqlscript");

		$salt  = genRandomPassword(32);
		$crypt = getCryptedPassword("$password", $salt);
		$dbencryptpassw = $crypt . ':' . $salt;

		$query = "UPDATE $new_db.jos_users SET username = '$name', password = '$dbencryptpassw', email = '$email' where username = 'admin'";
		mysql_query($query);

		echo "JCMS Database: ok".'<br>';
	}
else {	echo "this name is engaged";}



	if($site=='WORDPRESS') {
		// Script for Wordpress CMS
		$source		 = 'WPCMS';
		$destination = 'CLIENTS/'.$name;

		shell_exec("mkdir $destination");
		shell_exec("cp -apR $source/* $destination");	//copy_directory( $source, $destination );
		echo "BLOG Files copy: ok ".'<br>';

		$configphp = $destination.'/wp-config.php';
		$tmp_name  = $destination.'/wp-config.php.tmp_name';
		$tmp_pass  = $destination.'/wp-config.php.tmp_pass';

		shell_exec("cat $configphp | sed s/@@VARIABLE@@/$name/mg > $tmp_name");
		shell_exec("cat $tmp_name  | sed s/@@PASSWORD@@/$password/mg > $tmp_pass");

		$tmp_unique1  = $destination.'/wp-config.php.tmp_uniqe1';
		$tmp_unique2  = $destination.'/wp-config.php.tmp_uniqe2';
		$tmp_unique3  = $destination.'/wp-config.php.tmp_uniqe3';
		$tmp_unique4  = $destination.'/wp-config.php.tmp_uniqe4';
		$tmp_unique5  = $destination.'/wp-config.php.tmp_uniqe5';
		$tmp_unique6  = $destination.'/wp-config.php.tmp_uniqe6';
		$tmp_unique7  = $destination.'/wp-config.php.tmp_uniqe7';
		$tmp_unique8  = $destination.'/wp-config.php.tmp_uniqe8';

		$unique1 = random(64);
		$unique2 = random(64);
		$unique3 = random(64);
		$unique4 = random(64);
		$unique5 = random(64);
		$unique6 = random(64);
		$unique7 = random(64);
		$unique8 = random(64);

		shell_exec("cat $tmp_pass	 | sed s/@@UNIQUE1@@/$unique1/mg > $tmp_unique1");
		shell_exec("cat $tmp_unique1 | sed s/@@UNIQUE2@@/$unique2/mg > $tmp_unique2");
		shell_exec("cat $tmp_unique2 | sed s/@@UNIQUE3@@/$unique3/mg > $tmp_unique3");
		shell_exec("cat $tmp_unique3 | sed s/@@UNIQUE4@@/$unique4/mg > $tmp_unique4");
		shell_exec("cat $tmp_unique4 | sed s/@@UNIQUE5@@/$unique5/mg > $tmp_unique5");
		shell_exec("cat $tmp_unique5 | sed s/@@UNIQUE6@@/$unique6/mg > $tmp_unique6");
		shell_exec("cat $tmp_unique6 | sed s/@@UNIQUE7@@/$unique7/mg > $tmp_unique7");
		shell_exec("cat $tmp_unique7 | sed s/@@UNIQUE8@@/$unique8/mg > $tmp_unique8");
		shell_exec("mv  $tmp_unique8 $configphp");
		echo "BLOG Config File: ok ".'<br>';
		$new_db = "CakeBLOGdb_".$name;	//$host = 'localhost';

		mysql_query("create database $new_db");
		$dbpassw = $password.'_aNqHzQL9';
		$query = "grant all on $new_db.* to '$name'@'$host' identified by '$dbpassw';";// source '$sqlscript'";
		mysql_query($query);
		$sqlscript = 'wordpress_init_database.sql';
		passthru("nohup mysql -u root -p'ENTER_PASSWORD_HERE' $new_db < $sqlscript");
		require('WPCMS/wp-includes/class-phpass.php');

		$PH = new PasswordHash(8, TRUE);
		$dbencryptpassw = $PH->crypt_private($password, '$P$B88kjtXBJ');
		$query = "UPDATE $new_db.wp_options SET option_value = 'http://$serverurl/$destination' where option_name = 'siteurl'";
		mysql_query($query);
		$query = "UPDATE $new_db.wp_options SET option_value = '$name Blog' where option_name = 'blogname'";
		mysql_query($query);
		$query = "UPDATE $new_db.wp_options SET option_value = 'http://$serverurl/$destination' where option_name = 'home'";
		mysql_query($query);
		$query = "UPDATE $new_db.wp_users SET user_login = '$name', user_pass = '$dbencryptpassw', user_nicename = '$fname', display_name = '$name' where user_login = 'admin'";
		// echo 'query = '.$query.'<br>';
		mysql_query($query);

		echo "BLOG Database: ok ".'<br>';
	}
else {	echo "this name is engaged";}





//		Script for	vTigerCRM
if($site=='VTIGER') {
	$source		 = 'VtigerCRM';
	$destination = 'CLIENTS/'.$name;
	shell_exec("mkdir $destination");
	shell_exec("cp -apR $source/* $destination");	//copy_directory( $source, $destination );
	echo " CRM Files copy: ok".'<br>';

	$configincphp = $destination.'/config.inc.php';
	$tmp1 		  = $destination.'/config.inc.php.tmp1';
	$tmp2         = $destination.'/config.inc.php.tmp2';
	$tmp3         = $destination.'/config.inc.php.tmp3';
	$tmp4         = $destination.'/config.inc.php.tmp4';
	$unique = random(32);

	shell_exec("cat $configincphp | sed s/@@VARIABLE@@/$name/mg > $tmp1");
	shell_exec("cat $tmp1 | sed s/@@PASSWORD@@/$password/mg > $tmp2");
	shell_exec("cat $tmp2 | sed s/@@UNIQUE@@/$unique/mg > $tmp3");
	shell_exec("mv  $tmp3 $configincphp");

	echo " CRM Config File: ok".'<br>';

//	$src = 'CLIENTS/'.$name;	$dst = $src.'/CRM';
//	shell_exec("cat $tmp3 | sed s/$src/$dst/mg > $tmp4");
//	shell_exec("mv  $tmp4 $configincphp");

//	$link = mysql_connect("localhost","root","ENTER_PASSWORD_HERE");
	$new_db = "CakeCRMdb_".$name;	//$host = 'localhost';

	mysql_query("create database $new_db");
	$dbpassw = $password.'_aNqHzQL9';
	$query = "grant all on $new_db.* to '$name'@'$host' identified by '$dbpassw';";// source '$sqlscript'";
	mysql_query($query);
	//mysql_query("CREATE TABLE `q2` (`field` INT NOT NULL ,PRIMARY KEY (  `field` ))");
	//$sqlscript = 'sql.sql';	//
	$sqlscript = 'crm_init_database.sql';
	passthru("nohup mysql -u root -p'ENTER_PASSWORD_HERE' $new_db < $sqlscript");

	function getencryptpass($user, $pass){
		$salt = substr($user, 0, 2);
		$salt = '$1$' . $salt . '$';
		return crypt($pass, $salt);
	}

	$dbencryptpassw = getencryptpass($name,$password);
	//$qwery = "INSERT into 'vtiger_users' ('user_name','user_password', 'crypt_type') values ('$name', '$dbencryptpassw','PHP5.3MD5')";
	$query = "UPDATE $new_db.vtiger_users SET user_name = '$name', user_password = '$dbencryptpassw', email1 = '$email', crypt_type = 'MD5' where user_name = 'admin'";
	mysql_query($query);

	echo " CRM Database: ok".'<br>';
}

else {	echo "this name is engaged";}
}
?>
