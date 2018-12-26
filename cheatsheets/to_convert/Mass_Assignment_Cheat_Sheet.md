---
title: Mass Assignment Cheat Sheet
permalink: /Mass_Assignment_Cheat_Sheet/
---

`__NOTOC__`

<div style="width:100%;height:160px;border:0,margin:0;overflow: hidden;">
[link=](/File:Cheatsheets-header.jpg\ "wikilink")

</div>
{\\| style="padding: 0;margin:0;margin-top:10px;text-align:left;" \\|- \\| valign="top" style="border-right: 1px dotted gray;padding-right:25px;" \\| Last revision (mm/dd/yy): **//**

<div class="noautonum">
__TOC__

</div>
Introduction
============

### Definition

Software frameworks sometime allow developers to automatically bind HTTP request parameters into program code variables or objects to make using that framework easier on developers. This can sometimes cause harm. Attackers can sometimes use this methodology to create new parameters that the developer never intended which in turn creates or overwrites new variable or objects in program code that was not intended. This is called a <i>mass assignment</i> vulnerability.

### Alternative Names

Depending on the language/framework in question, this vulnerability can have several [alternative names](https://cwe.mitre.org/data/definitions/915.html)

-   Mass Assignment: Ruby on Rails, NodeJS
-   Autobinding: Spring MVC, ASP.NET MVC
-   Object injection: PHP

### Example

Suppose there is a form for editing a user's account information:

<form>
`     `<input name=userid type=text>
`     `<input name=password type=text>
`     `<input name=email text=text>
`     `<input type=submit>
`  `

</form>
Here is the object that the form is binding to:

`  public class User {`
`     private String userid;`
`     private String password;`
`     private String email;`
`     private boolean isAdmin;`
`   `
`     //Getters & Setters`
`   }`

Here is the controller handling the request:

`  @RequestMapping(value = "/addUser", method = RequestMethod.POST)`
`  public String submit(User user) {`
`     `
`     userService.add(user);`
`  `
`     return "successPage";`
`  }`

Here is the typical request:

`  POST /addUser`
`  `
`  userid=bobbytables&password=hashedpass&email=bobby@tables.com`

And here is the exploit:

`  POST /addUser`
`  `
`  userid=bobbytables&password=hashedpass&email=bobby@tables.com&isAdmin=true`

### Exploitability

This functionality becomes exploitable when:

-   Attacker can guess common sensitive fields
-   Attacker has access to source code and can review the models for sensitive fields
-   AND the object with sensitive fields has an empty constructor

### Case Studies

#### GitHub

In 2012, GitHub was hacked using mass assignment. A user was able to upload his public key to any organization and thus make any subsequent changes in their repositories. [GitHub's Blog Post](https://github.com/blog/1068-public-key-security-vulnerability-and-mitigation)

### Solutions

-   Whitelist the bindable, non-sensitive fields
-   Blacklist the non-bindable, sensitive fields
-   Use Data Transfer Objects (DTOs)

General Solutions
=================

### Data Transfer Objects (DTOs)

An architectural approach is to create Data Transfer Objects and avoid binding input directly to domain objects. Only the fields that are meant to be editable by the user are included in the DTO.

`  public class UserRegistrationFormDTO {`
`     private String userid;`
`     private String password;`
`     private String email;`
`  `
`     //NOTE: isAdmin field is not present`
`   `
`     //Getters & Setters`
`   }`

Language & Framework Specific Solutions
=======================================

Spring MVC
----------

### Whitelisting

`  @Controller`
`  public class UserController`
`  {`
`     @InitBinder`
`     public void initBinder(WebDataBinder binder, WebRequest request)`
`     {`
`        binder.setAllowedFields(["userid","password","email"]);`
`     }`
`  `
`     ...`
`  }`

\[<http://docs.spring.io/spring/docs/current/javadoc-api/org/springframework/validation/DataBinder.html#setAllowedFields-java.lang.String>...- Reference\]

### Blacklisting

`  @Controller`
`  public class UserController`
`  {`
`     @InitBinder`
`     public void initBinder(WebDataBinder binder, WebRequest request)`
`     {`
`        binder.setDisallowedFields(["isAdmin"]);`
`     }`
`  `
`     ...`
`  }`

\[<http://docs.spring.io/spring/docs/current/javadoc-api/org/springframework/validation/DataBinder.html#setDisallowedFields-java.lang.String>...- Reference\]

NodeJS + Mongoose
-----------------

### Whitelisting

`  var UserSchema = new mongoose.Schema({`
`    userid    : String,`
`    password  : String,`
`    email     : String,`
`    isAdmin   : Boolean,`
`  });`
`  `
`  UserSchema.statics = {`
`      User.userCreateSafeFields: ['userid', 'password', 'email']`
`  };`
`  `
`  var User = mongoose.model('User', UserSchema);`

`  _ = require('underscore');`
`  var user = new User(_.pick(req.body, User.userCreateSafeFields));`

[Reference](http://underscorejs.org/#pick) [Reference](https://nvisium.com/blog/2014/01/17/insecure-mass-assignment-prevention/)

### Blacklisting

`  var massAssign = require('mongoose-mass-assign');`
`   `
`  var UserSchema = new mongoose.Schema({`
`    userid    : String,`
`    password  : String,`
`    email     : String,`
`    isAdmin   : { type: Boolean, protect: true, default: false }`
`  });`
`   `
`  UserSchema.plugin(massAssign);`
`   `
`  var User = mongoose.model('User', UserSchema);`

`  /** Static method, useful for creation **/`
`  var user = User.massAssign(req.body);`
`  `
`  /** Instance method, useful for updating  **/`
`  var user = new User;`
`  user.massAssign(req.body);`
`  `
`  /** Static massUpdate method **/`
`  var input = { userid: 'bhelx', isAdmin: 'true' };  `
`  User.update({ '_id': someId }, { $set: User.massUpdate(input) }, console.log);`

[Reference](https://www.npmjs.com/package/mongoose-mass-assign)

Ruby On Rails
-------------

[Reference](http://guides.rubyonrails.org/v3.2.9/security.html#mass-assignment)

Django
------

[Reference](https://coffeeonthekeyboard.com/mass-assignment-security-part-10-855/)

ASP.NET
-------

[Reference](http://odetocode.com/Blogs/scott/archive/2012/03/11/complete-guide-to-mass-assignment-in-asp-net-mvc.aspx)

PHP Laravel + Eloquent
----------------------

### Whitelisting

`  <?php`
`  `
`  namespace App;`
`  `
`  use Illuminate\Database\Eloquent\Model;`
`  `
`  class User extends Model`
`  {`
`     private $userid;`
`     private $password;`
`     private $email;`
`     private $isAdmin;`
`  `
`     protected $fillable = array('userid','password','email');`
`  `
`  }`

[Reference](https://laravel.com/docs/5.2/eloquent#mass-assignment)

### Blacklisting

`  <?php`
`  `
`  namespace App;`
`  `
`  use Illuminate\Database\Eloquent\Model;`
`  `
`  class User extends Model`
`  {`
`     private $userid;`
`     private $password;`
`     private $email;`
`     private $isAdmin;`
`  `
`     protected $guarded = array('isAdmin');`
`  `
`  }`

[Reference](https://laravel.com/docs/5.2/eloquent#mass-assignment)

Grails
------

[Reference](http://spring.io/blog/2012/03/28/secure-data-binding-with-grails/)

Play
----

[Reference](https://www.playframework.com/documentation/1.4.x/controllers#nobinding)

Jackson (JSON Object Mapper)
----------------------------

[Reference](http://www.baeldung.com/jackson-field-serializable-deserializable-or-not) [Reference](http://lifelongprogrammer.blogspot.com/2015/09/using-jackson-view-to-protect-mass-assignment.html)

GSON (JSON Object Mapper)
-------------------------

[Reference](https://sites.google.com/site/gson/gson-user-guide#TOC-Excluding-Fields-From-Serialization-and-Deserialization) [Reference](http://stackoverflow.com/a/27986860)

JSON-Lib (JSON Object Mapper)
-----------------------------

[Reference](http://json-lib.sourceforge.net/advanced.html)

Flexjson (JSON Object Mapper)
-----------------------------

[Reference](http://flexjson.sourceforge.net/#Serialization)

Authors and Primary Editors
===========================

-   [Abashkin Anton](mailto:abashkin.anton@gmail.com)

References and future reading
=============================

-   Mass Assignment, Rails and You <http://code.tutsplus.com/tutorials/mass-assignment-rails-and-you--net-31695>

Other Cheatsheets
=================

\\|}

[Category:Cheatsheets](/Category:Cheatsheets "wikilink")