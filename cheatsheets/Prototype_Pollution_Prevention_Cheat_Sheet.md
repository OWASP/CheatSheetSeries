# Prototype Pollution Prevention Cheat Sheet

## Explanation

Prototype Pollution is a critical vulnerability that can allow attackers to manipulate an application's JavaScript objects and properties, leading to serious security issues such as unauthorized access to data, privilege escalation, and even remote code execution.

For examples of why this is dangerous, see the links in the [Other resources](#other-resources) section below.

## Suggested protection mechanisms

### Use "new Set()" or "new Map()"

Developers should use `new Set()` or `new Map()` instead of using object literals:

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

### If objects or object literals are required

If objects have to be used then they should be created using the `Object.create(null)` API to ensure they don't inherit from the Object prototype:

```javascript
let obj = Object.create(null);
```

If object literals are required then as a last resort you could use the `__proto__` property:

```javascript
let obj = {__proto__:null};
```

### Use object "freeze" and "seal" mechanisms

You can also use the `Object.freeze()` and `Object.seal()` APIs to prevent built-in prototypes from being modified however this can break the application if the libraries they use modify the built-in prototypes.

### Node.js configuration flag

Node.js also offers the ability to remove the `__proto__` property completely using the `--disable-proto=delete` flag. Note this is a defense in depth measure.

Prototype pollution is still possible using `constructor.prototype` properties but removing `__proto__` helps reduce attack surface and prevent certain attacks.

### Other resources

- [What is prototype pollution? (Portswigger Web Security Academy)](https://portswigger.net/web-security/prototype-pollution)
- [Prototype pollution (Snyk Learn)](https://learn.snyk.io/lessons/prototype-pollution/javascript/)

### Credits

Credit to [Gareth Hayes](https://garethheyes.co.uk/) for providing the original protection guidance [in this comment](https://github.com/OWASP/ASVS/issues/1563#issuecomment-1470027723).
