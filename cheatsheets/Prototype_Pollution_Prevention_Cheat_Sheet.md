# 原型污染预防备忘录

## 解释

原型污染是一个关键的漏洞，攻击者可以通过它操纵应用程序的 JavaScript 对象和属性，导致严重的安全问题，如未经授权访问数据、权限提升，甚至远程代码执行。

关于为什么这是危险的具体示例，请参见下面[其他资源](#其他资源)部分的链接。

## 建议的保护机制

### 使用 "new Set()" 或 "new Map()"

开发者应使用 `new Set()` 或 `new Map()` 而不是使用对象字面量：

```javascript
let allowedTags = new Set();
allowedTags.add('b');
if(allowedTags.has('b')){
  //...
}

let options = new Map();
options.set('spaces', 1);
let spaces = options.get('spaces')
```

### 如果需要对象或对象字面量

如果必须使用对象，则应使用 `Object.create(null)` API 创建，以确保它们不继承自 Object 原型：

```javascript
let obj = Object.create(null);
```

如果需要对象字面量，作为最后的手段，可以使用 `__proto__` 属性：

```javascript
let obj = {__proto__:null};
```

### 使用对象"冻结"和"密封"机制

您还可以使用 `Object.freeze()` 和 `Object.seal()` API 来防止修改内置原型，但如果使用的库修改了内置原型，这可能会破坏应用程序。

### Node.js 配置标志

Node.js 还提供了使用 `--disable-proto=delete` 标志完全删除 `__proto__` 属性的能力。请注意，这是深度防御措施。

使用 `constructor.prototype` 属性仍然可能发生原型污染，但删除 `__proto__` 有助于减少攻击面并防止某些攻击。

### 其他资源

- [什么是原型污染？（Portswigger Web 安全学院）](https://portswigger.net/web-security/prototype-pollution)
- [原型污染（Snyk 学习）](https://learn.snyk.io/lessons/prototype-pollution/javascript/)

### 致谢

感谢 [Gareth Hayes](https://garethheyes.co.uk/) 在[此评论](https://github.com/OWASP/ASVS/issues/1563#issuecomment-1470027723)中提供原始的保护指导。
