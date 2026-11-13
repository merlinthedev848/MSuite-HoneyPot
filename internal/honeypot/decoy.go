package honeypot

const FakeWordPressLogin = `<!DOCTYPE html>
<html lang="en-US">
<head>
	<meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />
	<title>Log In &lsaquo; WordPress</title>
	<style>
		body { background: #f0f0f1; font-family: -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Oxygen-Sans,Ubuntu,Cantarell,"Helvetica Neue",sans-serif; margin: 0; padding: 100px 0 0 0; }
		.login-box { width: 320px; margin: auto; background: #fff; padding: 26px 24px; border: 1px solid #c3c4c7; box-shadow: 0 1px 3px rgba(0,0,0,.04); }
		h1 { text-align: center; font-size: 20px; margin-bottom: 20px; }
		label { font-size: 14px; color: #3c434a; display: block; margin-bottom: 5px; }
		input[type="text"], input[type="password"] { width: 100%; box-sizing: border-box; padding: 6px 10px; margin-bottom: 15px; border: 1px solid #8c8f94; font-size: 16px; }
		input[type="submit"] { background: #2271b1; color: #fff; border: none; padding: 8px 15px; border-radius: 3px; cursor: pointer; font-size: 14px; width: 100%; }
	</style>
</head>
<body>
	<div class="login-box">
		<h1>WordPress Login</h1>
		<form method="post" action="/wp-login.php">
			<label>Username or Email Address</label>
			<input type="text" name="log" autocomplete="username" />
			<label>Password</label>
			<input type="password" name="pwd" autocomplete="current-password" />
			<input type="submit" value="Log In" />
		</form>
	</div>
</body>
</html>`

const FakeEnv = `APP_NAME=Laravel
APP_ENV=production
APP_KEY=base64:7vN4tS4uG5lP2r1Q9kX8yW3zV6mO1jR4tE7uI2oP5aA=
APP_DEBUG=false
APP_URL=https://localhost

LOG_CHANNEL=stack

DB_CONNECTION=mysql
DB_HOST=127.0.0.1
DB_PORT=3306
DB_DATABASE=app_production
DB_USERNAME=root
DB_PASSWORD=fake_honey_token_do_not_use

AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
`

const FakeNginxWelcome = `<!DOCTYPE html>
<html>
<head>
<title>Welcome to nginx!</title>
<style>
html { color-scheme: light dark; }
body { width: 35em; margin: 0 auto;
font-family: Tahoma, Verdana, Arial, sans-serif; }
</style>
</head>
<body>
<h1>Welcome to nginx!</h1>
<p>If you see this page, the nginx web server is successfully installed and
working. Further configuration is required.</p>

<p>For online documentation and support please refer to
<a href="http://nginx.org/">nginx.org</a>.<br/>
Commercial support is available at
<a href="http://nginx.com/">nginx.com</a>.</p>

<p><em>Thank you for using nginx.</em></p>
</body>
</html>`

const FakeGitConfig = `[core]
	repositoryformatversion = 0
	filemode = true
	bare = false
	logallrefupdates = true
[remote "origin"]
	url = git@github.com:internal/infra-core.git
	fetch = +refs/heads/*:refs/remotes/origin/*
[branch "main"]
	remote = origin
	merge = refs/heads/main
`
