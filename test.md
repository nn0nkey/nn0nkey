# 对spring-blade框架站点的渗透技术分享

## 前言

在当今网络安全环境中，Web应用程序的安全性已成为企业及个人站点防护的重中之重。随着开源框架和快速开发工具的普及，诸如Blade这样的轻量级Java Web框架得到了广泛应用。然而，随着Web应用的广泛部署，黑客及恶意攻击者也在不断寻找漏洞，以利用框架或其部署的潜在缺陷进行入侵。为确保系统的安全性，定期进行渗透测试显得尤为重要。

文章中涉及的敏感信息均已做打码处理，文章仅做经验分享用途，切勿当真，未授权的攻击属于非法行为！文章中敏感信息均已做多层打码处理。传播、利用本文章所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，作者不为此承担任何责任，一旦造成后果请自行承担。

参考http://www.aqtd.com/nd.jsp?id=6693

## 站点信息寻找

一般我是通过图标去找的，因为特征感很强

https://sns.bladex.cn/article/2我随便搜了一下，有一个社区

![image-20240925204209323](https://gitee.com/nn0nkey/picture/raw/master/img/image-20240925204209323.png)

![image-20240925204226564](https://gitee.com/nn0nkey/picture/raw/master/img/image-20240925204226564.png)

这样的特征很多，只需要找出icon就ok了

fofa语法

```php
icon_hash="1047841028"
```

![image-20240925205427834](../AppData/Roaming/Typora/typora-user-images/image-20240925205427834.png)

可以看见还是很多的8000多个

hunter中

hunter可能更方便，进入站点，找到文件

![image-20240925205632142](https://gitee.com/nn0nkey/picture/raw/master/img/image-20240925205632142.png)

然后直接放到hunter

![image-20240925205708900](https://gitee.com/nn0nkey/picture/raw/master/img/image-20240925205708900.png)

```java
web.icon="952438bb6af042855ed192384032e37b"
```



![image-20240925205734065](https://gitee.com/nn0nkey/picture/raw/master/img/image-20240925205734065.png)



## 弱密码登录+爆破

我们随便找一个站

![image-20240925210029719](https://gitee.com/nn0nkey/picture/raw/master/img/image-20240925210029719.png)

可惜啊，这个验证码阻拦了我爆破的想法，可以试一试乱输入这个验证码会不会更新

![image-20240925210521869](https://gitee.com/nn0nkey/picture/raw/master/img/image-20240925210521869.png)

发现这个验证码根本不会更新，弱密码爆破一波


发现密码被hash了，找个hash的字典爆破一下，最后好在运气好，爆出来了一个

![image-20240925214528291](https://gitee.com/nn0nkey/picture/raw/master/img/image-20240925214528291.png)



在个人信息界面可以修改密码和上传头像

![image-20240925214613028](https://gitee.com/nn0nkey/picture/raw/master/img/image-20240925214613028.png)



尝试了文件上传的各种绕过，绕不过

发现这两个点是点不进去的，一点就说没有权限

![image-20240925214857504](https://gitee.com/nn0nkey/picture/raw/master/img/image-20240925214857504.png)



## 寻找数据文件

当时不是说了吗，我正常访问，返回如下

```java
{"code":401,"success":false,"data":{},"msg":"请求未授权"}
```

首先第一反应肯定是修改回包

```java
{"code":200,"success":true,"data":{},"msg":"success"}
```

但是不可以

一堆尝试修修改改一下

不行尝试读取一下日志文件

发现了登录信息，喜喜，还有admin，password是md5编码的，去解一下

![image-20240925220727199](https://gitee.com/nn0nkey/picture/raw/master/img/image-20240925220727199.png)



我们拿去爆破一下

![image-20240925220946777](https://gitee.com/nn0nkey/picture/raw/master/img/image-20240925220946777.png)

## admin权限用户

![image-20240925221549284](https://gitee.com/nn0nkey/picture/raw/master/img/image-20240925221549284.png)

可以看见admin用户功能点多了很多

![image-20240925221244029](https://gitee.com/nn0nkey/picture/raw/master/img/image-20240925221244029.png)



有大量的信息泄露

![image-20240925221459363](https://gitee.com/nn0nkey/picture/raw/master/img/image-20240925221459363.png)

获取了很多账号，嘿嘿嘿，又可以去爆破了，但是都有admin了，不需要多此一举了

可以查看日志记录，可以查看到其他用户登录的log，而且password都是一样的

![image-20240925222803858](https://gitee.com/nn0nkey/picture/raw/master/img/image-20240925222803858.png)

现在相当于获得所有的用户和密码了

![image-20240925222819555](https://gitee.com/nn0nkey/picture/raw/master/img/image-20240925222819555.png)

## 远程jdbc连接

![image-20240925224023414](https://gitee.com/nn0nkey/picture/raw/master/img/image-20240925224023414.png)

可以看到是泄露了jdbc的密码和账号，还有jdbc连接的地址的，我们可以远程连接

sql语句select * from users

虽然报错了，但是证明连接是成功了

```java
Exception in thread "main" java.sql.SQLSyntaxErrorException: Table 'construct.users' doesn't exist
	at com.mysql.cj.jdbc.exceptions.SQLError.createSQLException(SQLError.java:120)
	at com.mysql.cj.jdbc.exceptions.SQLError.createSQLException(SQLError.java:97)
	at com.mysql.cj.jdbc.exceptions.SQLExceptionsMapping.translateException(SQLExceptionsMapping.java:122)
	at com.mysql.cj.jdbc.StatementImpl.executeQuery(StatementImpl.java:1218)
	at MYSQL.JDBC_Connection_example.main(JDBC_Connection_example.java:20)

```

不过小问题，我们找找表的名字

![image-20240925224335022](https://gitee.com/nn0nkey/picture/raw/master/img/image-20240925224335022.png)

尝试查询一下

懒得打码了，如下

![image-20240925224423541](https://gitee.com/nn0nkey/picture/raw/master/img/image-20240925224423541.png)

然后尝试jdbc命令执行，但是发现不行，因为自己菜

当然都能够sql注入了，提取的方法还是有的，这里就不深入研究了

## 阿里云储存桶

可以看见是泄露了我们的key的，

![image-20240925215210204](https://gitee.com/nn0nkey/picture/raw/master/img/image-20240925215210204.png)

可以接管文件系统了

![image-20240926083954192](https://gitee.com/nn0nkey/picture/raw/master/img/image-20240926083954192.png)

可以任意文件读取和任意文件删除下载

## 应用密钥泄露

![](https://gitee.com/nn0nkey/picture/raw/master/img/image-20240926013848135.png)

## 任意文件上传

在这个位置我们可以选择上传图片，经过测试，后端是没有验证的

![image-20240926084544469](https://gitee.com/nn0nkey/picture/raw/master/img/image-20240926084544469.png)

保存后就上传成功

![image-20240926084726034](https://gitee.com/nn0nkey/picture/raw/master/img/image-20240926084726034.png)

点击可以下载

![image-20240926084743650](https://gitee.com/nn0nkey/picture/raw/master/img/image-20240926084743650.png)



不过对文件名做了处理，猜测是时间搓的md5

可以去验证一下

![image-20240926084904011](https://gitee.com/nn0nkey/picture/raw/master/img/image-20240926084904011.png)

确实是成功了

## 最后

文章中涉及的敏感信息均已做打码处理，文章仅做经验分享用途，切勿当真，未授权的攻击属于非法行为！文章中敏感信息均已做多层打码处理。传播、利用本文章所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，作者不为此承担任何责任，一旦造成后果请自行承担。
