# 批量赋值备忘录

## 引言

### 定义

软件框架有时允许开发者自动将HTTP请求参数绑定到程序代码变量或对象，以简化框架使用。但这有时可能会造成伤害。

攻击者有时可以使用这种方法创建开发者从未预期的新参数，进而在程序代码中创建或覆盖非预期的变量或对象。

这被称为**批量赋值**漏洞。

### 替代名称

根据所涉及的编程语言/框架，这个漏洞可能有几个[替代名称](https://cwe.mitre.org/data/definitions/915.html)：

- **批量赋值：** Ruby on Rails, NodeJS
- **自动绑定：** Spring MVC, ASP NET MVC
- **对象注入：** PHP

### 示例

假设有一个编辑用户账户信息的表单：

```html
<form>
     <input name="userid" type="text">
     <input name="password" type="text">
     <input name="email" text="text">
     <input type="submit">
</form>  
```

这是表单绑定的对象：

```java
public class User {
   private String userid;
   private String password;
   private String email;
   private boolean isAdmin;

   //Getter和Setter方法
}
```

处理请求的控制器：

```java
@RequestMapping(value = "/addUser", method = RequestMethod.POST)
public String submit(User user) {
   userService.add(user);
   return "successPage";
}
```

典型的请求：

```text
POST /addUser
...
userid=bobbytables&password=hashedpass&email=bobby@tables.com
```

攻击者利用的请求，设置`User`类实例的`isAdmin`属性：

```text
POST /addUser
...
userid=bobbytables&password=hashedpass&email=bobby@tables.com&isAdmin=true
```

### 可利用性

当以下条件同时满足时，这种功能变得可被利用：

- 攻击者可以猜测常见的敏感字段
- 攻击者可以访问源代码并查看模型中的敏感字段
- 且包含敏感字段的对象有一个空的构造函数

### GitHub案例研究

2012年，GitHub遭到批量赋值攻击。一个用户能够将自己的公钥上传到任何组织，从而可以对其仓库进行任何后续更改。[GitHub博客文章](https://blog.github.com/2012-03-04-public-key-security-vulnerability-and-mitigation/)

### 解决方案

- 允许列出可绑定的非敏感字段
- 阻止列出不可绑定的敏感字段
- 使用[数据传输对象](https://martinfowler.com/eaaCatalog/dataTransferObject.html)（DTOs）

## 通用解决方案

架构方法是创建数据传输对象（DTOs）并避免直接将输入绑定到域对象。只包含用户可编辑的字段。

```java
public class UserRegistrationFormDTO {
 private String userid;
 private String password;
 private String email;

 //注意：没有isAdmin字段

 //Getter和Setter方法
}
```

## 特定语言和框架的解决方案

### Spring MVC

#### 允许列表

```java
@Controller
public class UserController
{
    @InitBinder
    public void initBinder(WebDataBinder binder, WebRequest request)
    {
        binder.setAllowedFields(["userid","password","email"]);
    }
...
}
```

查看[文档](https://docs.spring.io/spring/docs/current/javadoc-api/org/springframework/validation/DataBinder.html#setAllowedFields-java.lang.String...-)了解更多。

#### 阻止列表

```java
@Controller
public class UserController
{
   @InitBinder
   public void initBinder(WebDataBinder binder, WebRequest request)
   {
      binder.setDisallowedFields(["isAdmin"]);
   }
...
}
```

查看[文档](https://docs.spring.io/spring/docs/current/javadoc-api/org/springframework/validation/DataBinder.html#setDisallowedFields-java.lang.String...-)了解更多。

### NodeJS + Mongoose

#### 允许列表

```javascript
var UserSchema = new mongoose.Schema({
    userid: String,
    password: String,
    email : String,
    isAdmin : Boolean,
});

UserSchema.statics = {
    User.userCreateSafeFields: ['userid', 'password', 'email']
};

var User = mongoose.model('User', UserSchema);

_ = require('underscore');
var user = new User(_.pick(req.body, User.userCreateSafeFields));
```

查看[文档](http://underscorejs.org/#pick)了解更多。

#### 阻止列表

```javascript
var massAssign = require('mongoose-mass-assign');

var UserSchema = new mongoose.Schema({
    userid: String,
    password: String,
    email : String,
    isAdmin : { type: Boolean, protect: true, default: false }
});

UserSchema.plugin(massAssign);

var User = mongoose.model('User', UserSchema);

/** 静态方法，适用于创建 **/
var user = User.massAssign(req.body);

/** 实例方法，适用于更新 **/
var user = new User;
user.massAssign(req.body);

/** 静态批量更新方法 **/
var input = { userid: 'bhelx', isAdmin: 'true' };
User.update({ '_id': someId }, { $set: User.massUpdate(input) }, console.log);
```

查看[文档](https://www.npmjs.com/package/mongoose-mass-assign)了解更多。

### Ruby On Rails

查看[文档](https://guides.rubyonrails.org/v3.2.9/security.html#mass-assignment)了解更多。

### Django

查看[文档](https://coffeeonthekeyboard.com/mass-assignment-security-part-10-855/)了解更多。

### ASP NET

查看[文档](https://odetocode.com/Blogs/scott/archive/2012/03/11/complete-guide-to-mass-assignment-in-asp-net-mvc.aspx)了解更多。

### PHP Laravel + Eloquent

#### 允许列表

```php
<?php

namespace App;

use Illuminate\Database\Eloquent\Model;

class User extends Model
{
    private $userid;
    private $password;
    private $email;
    private $isAdmin;

    protected $fillable = array('userid','password','email');
}
```

查看[文档](https://laravel.com/docs/5.2/eloquent#mass-assignment)了解更多。

#### 阻止列表

```php
<?php

namespace App;

use Illuminate\Database\Eloquent\Model;

class User extends Model
{
    private $userid;
    private $password;
    private $email;
    private $isAdmin;

    protected $guarded = array('isAdmin');
}
```

查看[文档](https://laravel.com/docs/5.2/eloquent#mass-assignment)了解更多。

### Grails

查看[文档](http://spring.io/blog/2012/03/28/secure-data-binding-with-grails/)了解更多。

### Play

查看[文档](https://www.playframework.com/documentation/1.4.x/controllers#nobinding)了解更多。

### Jackson（JSON对象映射器）

查看[文档1](https://www.baeldung.com/jackson-field-serializable-deserializable-or-not)和[文档2](http://lifelongprogrammer.blogspot.com/2015/09/using-jackson-view-to-protect-mass-assignment.html)了解更多。

### GSON（JSON对象映射器）

查看[文档1](https://sites.google.com/site/gson/gson-user-guide#TOC-Excluding-Fields-From-Serialization-and-Deserialization)和[文档2](https://stackoverflow.com/a/27986860)了解更多。

### JSON-Lib（JSON对象映射器）

查看[文档](http://json-lib.sourceforge.net/advanced.html)了解更多。

### Flexjson（JSON对象映射器）

查看[文档](http://flexjson.sourceforge.net/#Serialization)了解更多。

## 参考文献和进一步阅读

- [批量赋值、Rails和你](https://code.tutsplus.com/tutorials/mass-assignment-rails-and-you--net-31695)
