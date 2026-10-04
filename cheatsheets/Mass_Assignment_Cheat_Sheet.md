# Mass Assignment Cheat Sheet

## Introduction

### Definition

Software frameworks sometimes allow developers to automatically bind HTTP request parameters into program code variables or objects to make using that framework easier on developers. This can sometimes cause harm.

Attackers can sometimes use this methodology to create new parameters that the developer never intended which in turn creates or overwrites new variable or objects in program code that was not intended.

This is called a **Mass Assignment** vulnerability.

### Alternative Names

Depending on the language/framework in question, this vulnerability can have several [alternative names](https://cwe.mitre.org/data/definitions/915.html):

- **Mass Assignment:** Ruby on Rails, NodeJS.
- **Autobinding:** Spring MVC, ASP NET MVC.
- **Object injection:** PHP.

### Example

Suppose there is a form for editing a user's account information:

```html
<form>
     <input name="userid" type="text">
     <input name="password" type="text">
     <input name="email" text="text">
     <input type="submit">
</form>  
```

Here is the object that the form is binding to:

```java
public class User {
   private String userid;
   private String password;
   private String email;
   private boolean isAdmin;

   //Getters & Setters
}
```

Here is the controller handling the request:

```java
@RequestMapping(value = "/addUser", method = RequestMethod.POST)
public String submit(User user) {
   userService.add(user);
   return "successPage";
}
```

Here is the typical request:

```text
POST /addUser
...
userid=bobbytables&password=hashedpass&email=bobby@tables.com
```

And here is the exploit in which we set the value of the attribute `isAdmin` of the instance of the class `User`:

```text
POST /addUser
...
userid=bobbytables&password=hashedpass&email=bobby@tables.com&isAdmin=true
```

### Exploitability

Mass assignment is exploitable when attacker-controlled input can initialize or update fields that the caller is not authorized to change, such as a role or account owner. Field names may be guessed or discovered; source-code access is not required. [CWE-915](https://cwe.mitre.org/data/definitions/915.html) defines the weakness in terms of insufficient control over writable attributes.

An empty constructor is not a general prerequisite. For example, [Spring supports both constructor and setter binding](https://docs.spring.io/spring-framework/reference/web/webmvc/mvc-data-binding.html). Review which inputs the binding mechanism exposes, including nested objects.

### GitHub case study

In 2012, GitHub was hacked using mass assignment. A user was able to upload his public key to any organization and thus make any subsequent changes in their repositories. [GitHub's Blog Post](https://blog.github.com/2012-03-04-public-key-security-vulnerability-and-mitigation/).

### Solutions

- Prefer dedicated input objects, such as Data Transfer Objects (DTOs), containing only fields the caller may edit; see [Spring's model design guidance](https://docs.spring.io/spring-framework/reference/web/webmvc/mvc-data-binding.html).
- Explicitly allow-list fields when binding to an object with additional properties.
- Do not rely on a block-list as the sole protection: a new or overlooked sensitive field remains bindable. [CWE-915 recommends allowlists over denylists](https://cwe.mitre.org/data/definitions/915.html). The block-list examples below illustrate mechanisms encountered in existing applications, not the recommended design.

DTOs and field allowlists restrict writable properties; they do not replace [authorization for the requested object and operation](Authorization_Cheat_Sheet.md#validate-the-permissions-on-every-request).

## General Solutions

An architectural approach is to create Data Transfer Objects and avoid binding input directly to domain objects. Only the fields that are meant to be editable by the user are included in the DTO.

```java
public class UserRegistrationFormDTO {
 private String userid;
 private String password;
 private String email;

 //NOTE: isAdmin field is not present

 //Getters & Setters
}
```

## Language & Framework specific solutions

### Spring MVC

#### Allow-listing

```java
@Controller
public class UserController
{
    @InitBinder
    public void initBinder(WebDataBinder binder, WebRequest request)
    {
        binder.setAllowedFields("userid", "password", "email");
    }
...
}
```

See [Spring's model design guidance](https://docs.spring.io/spring-framework/reference/web/webmvc/mvc-data-binding.html) for dedicated input objects and allowed fields.

#### Block-listing

Spring describes `disallowedFields` as fragile because fields can be missed or added later. Prefer the allow-list above; this example only excludes the named property.

```java
@Controller
public class UserController
{
   @InitBinder
   public void initBinder(WebDataBinder binder, WebRequest request)
   {
      binder.setDisallowedFields("isAdmin");
   }
...
}
```

See the [Spring data binding limitations](https://docs.spring.io/spring-framework/reference/web/webmvc/mvc-data-binding.html).

### NodeJS + Mongoose

#### Allow-listing

```javascript
var UserSchema = new mongoose.Schema({
    userid: String,
    password: String,
    email : String,
    isAdmin : Boolean,
});

UserSchema.statics = {
    User.userCreateSafeFields: ['userid', 'password', 'email']
};

var User = mongoose.model('User', UserSchema);

_ = require('underscore');
var user = new User(_.pick(req.body, User.userCreateSafeFields));
```

Take a look [here](http://underscorejs.org/#pick) for the documentation.

#### Block-listing

```javascript
var massAssign = require('mongoose-mass-assign');

var UserSchema = new mongoose.Schema({
    userid: String,
    password: String,
    email : String,
    isAdmin : { type: Boolean, protect: true, default: false }
});

UserSchema.plugin(massAssign);

var User = mongoose.model('User', UserSchema);

/** Static method, useful for creation **/
var user = User.massAssign(req.body);

/** Instance method, useful for updating**/
var user = new User;
user.massAssign(req.body);

/** Static massUpdate method **/
var input = { userid: 'bhelx', isAdmin: 'true' };
User.update({ '_id': someId }, { $set: User.massUpdate(input) }, console.log);
```

Take a look [here](https://www.npmjs.com/package/mongoose-mass-assign) for the documentation.

### Ruby On Rails

Take a look [here](https://guides.rubyonrails.org/v3.2.9/security.html#mass-assignment) for the documentation.

### Django

Take a look [here](https://coffeeonthekeyboard.com/mass-assignment-security-part-10-855/) for the documentation.

### ASP NET

Take a look [here](https://odetocode.com/Blogs/scott/archive/2012/03/11/complete-guide-to-mass-assignment-in-asp-net-mvc.aspx) for the documentation.

### PHP Laravel + Eloquent

#### Allow-listing

```php
<?php

namespace App;

use Illuminate\Database\Eloquent\Model;

class User extends Model
{
    private $userid;
    private $password;
    private $email;
    private $isAdmin;

    protected $fillable = array('userid','password','email');
}
```

Take a look [here](https://laravel.com/docs/5.2/eloquent#mass-assignment) for the documentation.

#### Block-listing

```php
<?php

namespace App;

use Illuminate\Database\Eloquent\Model;

class User extends Model
{
    private $userid;
    private $password;
    private $email;
    private $isAdmin;

    protected $guarded = array('isAdmin');
}
```

Take a look [here](https://laravel.com/docs/5.2/eloquent#mass-assignment) for the documentation.

### Grails

Take a look [here](http://spring.io/blog/2012/03/28/secure-data-binding-with-grails/) for the documentation.

### Play

Take a look [here](https://www.playframework.com/documentation/1.4.x/controllers#nobinding) for the documentation.

### Jackson (JSON Object Mapper)

Take a look [here](https://www.baeldung.com/jackson-field-serializable-deserializable-or-not) and [here](http://lifelongprogrammer.blogspot.com/2015/09/using-jackson-view-to-protect-mass-assignment.html) for the documentation.

### GSON (JSON Object Mapper)

Take a look [here](https://sites.google.com/site/gson/gson-user-guide#TOC-Excluding-Fields-From-Serialization-and-Deserialization) and [here](https://stackoverflow.com/a/27986860) for the document.

### JSON-Lib (JSON Object Mapper)

Take a look [here](http://json-lib.sourceforge.net/advanced.html) for the documentation.

### Flexjson (JSON Object Mapper)

Take a look [here](http://flexjson.sourceforge.net/#Serialization) for the documentation.

## References

- [Ruby on Rails: Strong Parameters](https://guides.rubyonrails.org/action_controller_overview.html#strong-parameters)
- [Spring Framework: DataBinder Security Considerations](https://docs.spring.io/spring-framework/docs/current/javadoc-api/org/springframework/validation/DataBinder.html)
