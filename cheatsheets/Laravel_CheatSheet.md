# Laravel Cheat Sheet

## Introduction

This *Cheatsheet* intends to provide security tips to developers building Laravel applications. It aims to cover all common vulnerabilities and how to ensure that your Laravel applications are secure.

The Laravel Framework provides in-built security features and is meant to be secure by default. However, it also provides additional flexibility for complex use cases. This means that developers unfamiliar with the inner workings of Laravel may fall into the trap of using complex features in a way that is not secure. This guide is meant to educate developers to avoid common pitfalls and develop Laravel applications in a secure manner.

You may also refer the [Enlightn Security Documentation](https://www.laravel-enlightn.com/docs/security/), which highlights common vulnerabilities and good practices on securing Laravel applications.

## The Basics

- Make sure your app is not in debug mode while in production. To turn off debug mode, set your `APP_DEBUG` environment variable to `false`:

```ini
APP_DEBUG=false
```

- Make sure your application key has been generated. Laravel applications use the app key for symmetric encryption and SHA256 hashes such as cookie encryption, signed URLs, password reset tokens and session data encryption. To generate the app key, you may run the `key:generate` Artisan command:

```bash
php artisan key:generate
```

- Make sure your PHP configuration is secure. You may refer the [PHP Configuration Cheat Sheet](PHP_Configuration_Cheat_Sheet.md) for more information on secure PHP configuration settings.

- Set safe file and directory permissions on your Laravel application. In general, all Laravel directories should be setup with a max permission level of `775` and non-executable files with a max permission level of `664`. Executable files such as Artisan or deployment scripts should be provided with a max permission level of `775`.

- Make sure your application does not have vulnerable dependencies. You can check this using the [Enlightn Security Checker](https://github.com/enlightn/security-checker).

## Cookie Security and Session Management

By default, Laravel is configured in a secure manner. However, if you change your cookie or session configurations, make sure of the following:

- Enable the cookie encryption middleware if you use the `cookie` session store or if you store any kind of data that should not be readable or tampered with by clients. In general, this should be enabled unless your application has a very specific use case that requires disabling this. To enable this middleware, simply add the `EncryptCookies` middleware to the `web` middleware group in your `App\Http\Kernel` class:

```php
/**
 * The application's route middleware groups.
 *
 * @var array
 */
protected $middlewareGroups = [
    'web' => [
        \App\Http\Middleware\EncryptCookies::class,
        ...
    ],
    ...
];
```

- Enable the `HttpOnly` attribute on your session cookies via your `config/session.php` file, so that your session cookies are inaccessible from Javascript:

```php
'http_only' => true,
```

- Unless you are using sub-domain route registrations in your Laravel application, it is recommended to set the cookie `domain` attribute to null so that only the same origin (excluding subdomains) can set the cookie. This can be configured in your `config/session.php` file:

```php
'domain' => null,
```

- Set your `SameSite` cookie attribute to `lax` or `strict` in your `config/session.php` file to restrict your cookies to a first-party or same-site context:

```php
'same_site' => 'lax',
```

- If your application is HTTPS only, it is recommended to set the `secure` configuration option in your `config/session.php` file to `true` to protect against man-in-the-middle attacks. If your application has a combination of HTTP and HTTPS, then it is recommended to set this value to `null` so that the secure attribute is set automatically when serving HTTPS requests:

```php
'secure' => null,
```

- Ensure that you have a low session idle timeout value. [OWASP recommends](Session_Management_Cheat_Sheet.md) a 2-5 minutes idle timeout for high value applications and 15-30 minutes for low risk applications. This can be configured in your `config/session.php` file:

```php
'lifetime' => 15,
```

You may also refer the [Cookie Security Guide](https://owasp.org/www-chapter-london/assets/slides/OWASPLondon20171130_Cookie_Security_Myths_Misconceptions_David_Johansson.pdf) to learn more about cookie security and the cookie attributes mentioned above.

## Authentication

### Guards and Providers

At its core, Laravel's authentication facilities are made up of "guards" and "providers". Guards define how users are authenticated for each request. Providers define how users are retrieved from your persistent storage.

Laravel ships with a `session` guard which maintains state using session storage and cookies, and a `token` guard for API tokens.

For providers, Laravel ships with a `eloquent` provider for retrieving users using the Eloquent ORM and the `database` provider for retrieving users using the database query builder.

Guards and providers can be configured in the `config/auth.php` file. Laravel offers the ability to build custom guards and providers as well.

### Starter Kits

Laravel offers a wide variety of first party application starter kits that include in-built authentication features:

1. [Laravel Breeze](https://laravel.com/docs/8.x/starter-kits#laravel-breeze): A simple, minimal implementation of all Laravel's authentication features including login, registration, password reset, email verification and password confirmation.
2. [Laravel Fortify](https://laravel.com/docs/fortify): A headless authentication backend that includes the above authentication features along with two-factor authentication.
3. [Laravel Jetstream](https://jetstream.laravel.com/): An application starter kit that provides a UI on top of Laravel Fortify's authentication features.

It is recommended to use one of these starter kits to ensure robust and secure authentication for your Laravel applications.

### API Authentication Packages

Laravel also offers the following API authentication packages:

1. [Passport](https://laravel.com/docs/passport): An OAuth2 authentication provider.
2. [Sanctum](https://laravel.com/docs/sanctum): An API token authentication provider.

Starter kits such as Fortify and Jetstream have in-built support for Sanctum.

## Mass Assignment

[Mass assignment](Mass_Assignment_Cheat_Sheet.md) is a common vulnerability in modern web applications that use an ORM like Laravel's Eloquent ORM.

A mass assignment is a vulnerability where an ORM pattern is abused to modify data items that the user should not be normally allowed to modify.

Consider the following code:

```php
Route::any('/profile', function (Request $request) {
    $request->user()->forceFill($request->all())->save();

    $user = $request->user()->fresh();

    return response()->json(compact('user'));
})->middleware('auth');
```

The above profile route allows the logged in user to change their profile information.

However, let's say there is an `is_admin` column in the users table. You probably do not want the user to be allowed to change the value of this column. However, the above code allows users to change any column values for their row in the users table. This is a mass assignment vulnerability.

Laravel has in-built features by default to protect against this vulnerability. Make sure of the following to stay secure:

- Qualify the allowed parameters that you wish to update using `$request->only` or `$request->validated` rather than `$request->all`.
- Do not unguard models or set the `$guarded` variable to an empty array. By doing this, you are actually disabling Laravel's in-built mass assignment protection.
- Avoid using methods such as `forceFill` or `forceCreate` that bypass the protection mechanism. You may however use these methods if you are passing in a validated array of values.

## SQL Injection

SQL Injection attacks are unfortunately quite common in modern web applications and entail attackers providing malicious request input data to interfere with SQL queries. This guide covers SQL injection and how it can be prevented specifically for Laravel applications. You may also refer the [SQL Injection Prevention Cheatsheet](SQL_Injection_Prevention_Cheat_Sheet.md) for more information that is not specific to Laravel.

### Eloquent ORM SQL Injection Protection

By default, Laravel's Eloquent ORM protects against SQL injection by parameterizing queries and using SQL bindings. For instance, consider the following query:

```php
use App\Models\User;

User::where('email', $email)->get();
```

The code above fires the query below:

```sql
select * from `users` where `email` = ?
```

So, even if `$email` is untrusted user input data, you are protected from SQL injection attacks.

### Raw Query SQL Injection

Laravel also offers raw query expressions and raw queries to construct complex queries or database specific queries that aren't supported out of the box.

While this is great for flexibility, you must be careful to always use SQL data bindings for such queries. Consider the following query:

```php
use Illuminate\Support\Facades\DB;
use App\Models\User;

User::whereRaw('email = "'.$request->input('email').'"')->get();
DB::table('users')->whereRaw('email = "'.$request->input('email').'"')->get();
```

Both lines of code actually execute the same query, which is vulnerable to SQL injection as the query does not use SQL bindings for untrusted user input data.

The code above fires the following query:

```sql
select * from `users` where `email` = "value of email query parameter"
```

Always remember to use SQL bindings for request data. We can fix the above code by making the following modification:

```php
use App\Models\User;

User::whereRaw('email = ?', [$request->input('email')])->get();
```

We can even use named SQL bindings like so:

```php
use App\Models\User;

User::whereRaw('email = :email', ['email' => $request->input('email')])->get();
```

### Column Name SQL Injection

You must never allow user input data to dictate column names referenced by your queries.

The following queries may be vulnerable to SQL injection:

```php
use App\Models\User;

User::where($request->input('colname'), 'somedata')->get();
User::query()->orderBy($request->input('sortBy'))->get();
```

It is important to note that even though Laravel has some in-built features such as wrapping column names to protect against the above SQL injection vulnerabilities, some database engines (depending on versions and configurations) may still be vulnerable because binding column names is not supported by databases.

At the very least, this may result in a mass assignment vulnerability instead of a SQL injection because you may have expected a certain set of column values, but since they are not validated here, the user is free to use other columns as well.

Always validate user input for such situations like so:

```php
use App\Models\User;

$request->validate(['sortBy' => 'in:price,updated_at']);
User::query()->orderBy($request->validated()['sortBy'])->get();
```

### Validation Rule SQL Injection

Certain validation rules have the option of providing database column names. Such rules are vulnerable to SQL injection in the same manner as column name SQL injection because they construct queries in a similar manner.

For example, the following code may be vulnerable:

```php
use Illuminate\Validation\Rule;

$request->validate([
    'id' => Rule::unique('users')->ignore($id, $request->input('colname'))
]);
```

Behind the scenes, the above code triggers the following query:

```php
use App\Models\User;

$colname = $request->input('colname');
User::where($colname, $request->input('id'))->where($colname, '<>', $id)->count();
```

Since the column name is dictated by user input, it is similar to column name SQL injection.

## Cross Site Scripting (XSS)

[XSS attacks](https://owasp.org/www-community/attacks/xss/) are injection attacks where malicious scripts (such as JavaScript code snippets) are injected into trusted websites.

Laravel's [Blade templating engine](https://laravel.com/docs/blade) has echo statements `{{ }}` that automatically escape variables using the `htmlspecialchars` PHP function to protect against XSS attacks.

Laravel also offers displaying unescaped data using the unescaped syntax `{!! !!}`. This must not be used on any untrusted data, otherwise your application will be subject to an XSS attack.

For instance, if you have something like this in any of your Blade templates, it would result in a vulnerability:

```blade
{!! request()->input('somedata') !!}
```

This, however, is safe to do:

```blade
{{ request()->input('somedata') }}
```

For other information on XSS prevention that is not specific to Laravel, you may refer the [Cross Site Scripting Prevention Cheatsheet](Cross_Site_Scripting_Prevention_Cheat_Sheet.md).

## Unrestricted File Uploads

Unrestricted file upload attacks entail attackers uploading malicious files to compromise web applications. This section describes how to protect against such attacks while building Laravel applications. You may also refer the [File Upload Cheatsheet](File_Upload_Cheat_Sheet.md) to learn more.

### Always Validate File Type and Size

Always validate the file type (extension or MIME type) and file size to avoid storage DOS attacks and remote code execution:

```php
$request->validate([
    'photo' => 'file|size:100|mimes:jpg,bmp,png'
]);
```

Storage DOS attacks exploit missing file size validations and upload massive files to cause a denial of service (DOS) by exhausting the disk space.

Remote code execution attacks entail first, uploading malicious executable files (such as PHP files) and then, triggering their malicious code by visiting the file URL (if public).

Both these attacks can be avoided by simple file validations as mentioned above.

### Do Not Rely On User Input To Dictate Filenames or Path

If your application allows user controlled data to construct the path of a file upload, this may result in overwriting a critical file or storing the file in a bad location.

Consider the following code:

```php
Route::post('/upload', function (Request $request) {
    $request->file('file')->storeAs(auth()->id(), $request->input('filename'));

    return back();
});
```

This route saves a file to a directory specific to a user ID. Here, we rely on the `filename` user input data and this may result in a vulnerability as the filename could be something like `../2/filename.pdf`. This will upload the file in user ID 2's directory instead of the directory pertaining to the current logged in user.

To fix this, we should use the `basename` PHP function to strip out any directory information from the `filename` input data:

```php
Route::post('/upload', function (Request $request) {
    $request->file('file')->storeAs(auth()->id(), basename($request->input('filename')));

    return back();
});
```

### Avoid Processing ZIP or XML Files If Possible

XML files can expose your application to a wide variety of attacks such as XXE attacks, the billion laughs attack and others. If you process ZIP files, you may be exposed to zip bomb DOS attacks.

Refer the [XML Security Cheatsheet](XML_Security_Cheat_Sheet.md) and the [File Upload Cheatsheet](File_Upload_Cheat_Sheet.md) to learn more.

## Path Traversal

A path traversal attack aims to access files by manipulating request input data with `../` sequences and variations or by using absolute file paths.

If you allow users to download files by filename, you may be exposed to this vulnerability if input data is not stripped of directory information.

Consider the following code:

```php
Route::get('/download', function(Request $request) {
    return response()->download(storage_path('content/').$request->input('filename'));
});
```

Here, the filename is not stripped of directory information, so a malformed filename such as `../../.env` could expose your application credentials to potential attackers.

Similar to unrestricted file uploads, you should use the `basename` PHP function to strip out directory information like so:

```php
Route::get('/download', function(Request $request) {
    return response()->download(storage_path('content/').basename($request->input('filename')));
});
```

## Open Redirection

Open Redirection attacks in themselves are not that dangerous but they enable phishing attacks.

Consider the following code:

```php
Route::get('/redirect', function (Request $request) {
   return redirect($request->input('url'));
});
```

This code redirects the user to any external URL provided by user input. This could enable attackers to create seemingly safe URLs like `https://example.com/redirect?url=http://evil.com`. For instance, attackers may use a URL of this type to spoof password reset emails and lead victims to expose their credentials on the attacker's website.

## Cross Site Request Forgery (CSRF)

[Cross-Site Request Forgery (CSRF)](https://owasp.org/www-community/attacks/csrf) is a type of attack that occurs when a malicious web site, email, blog, instant message, or program causes a user's web browser to perform an unwanted action on a trusted site when the user is authenticated.

Laravel provides CSRF protection out-of-the-box with the `VerifyCSRFToken` middleware. Generally, if you have this middleware in the `web` middleware group of your `App\Http\Kernel` class, you should be well protected:

```php
/**
 * The application's route middleware groups.
 *
 * @var array
 */
protected $middlewareGroups = [
    'web' => [
        ...
         \App\Http\Middleware\VerifyCsrfToken::class,
         ...
    ],
];
```

Next, for all your `POST` request forms, you may use the `@csrf` blade directive to generate the hidden CSRF input token fields:

```html
<form method="POST" action="/profile">
    @csrf

    <!-- Equivalent to... -->
    <input type="hidden" name="_token" value="{{ csrf_token() }}" />
</form>
```

For AJAX requests, you can setup the [X-CSRF-Token header](https://laravel.com/docs/csrf#csrf-x-csrf-token).

Laravel also provides the ability to exclude certain routes from CSRF protection using the `$except` variable in your CSRF middleware class. Typically, you would want to exclude only stateless routes (e.g. APIs or webhooks) from CSRF protection. If any other routes are excluded, these may result in CSRF vulnerabilities.

## Command Injection

Command Injection vulnerabilities involve executing shell commands constructed with unescaped user input data.

For example, the following code performs a `whois` on a user provided domain name:

```php
public function verifyDomain(Request $request)
{
    exec('whois '.$request->input('domain'));
}
```

The above code is vulnerable as the user data is not escaped properly. To do so, you may use the `escapeshellcmd` and/or `escapeshellarg` PHP functions.

## Other Injections

Object injection, eval code injection and extract variable hijacking attacks involve unserializing, evaluating or using the `extract` function on untrusted user input data.

Some examples are:

```php
unserialize($request->input('data'));
eval($request->input('data'));
extract($request->all());
```

In general, avoid passing any untrusted input data to these dangerous functions.

## Security Headers

You should consider adding the following security headers to your web server or Laravel application middleware:

- X-Frame-Options
- X-Content-Type-Options
- Strict-Transport-Security (for HTTPS only applications)
- Content-Security-Policy

For more information, refer the [OWASP secure headers project](https://owasp.org/www-project-secure-headers/).

## Tools

You should consider using [Enlightn](https://www.laravel-enlightn.com/), a static and dynamic analysis tool for Laravel applications that has over 45 automated security checks to identify potential security issues. There is both an open source version and a commercial version of Enlightn available. Enlightn includes an extensive 45 page documentation on security vulnerabilities and a great way to learn more on Laravel security is to just review its [documentation](https://www.laravel-enlightn.com/docs/security/).

You should also use the [Enlightn Security Checker](https://github.com/enlightn/security-checker) or the [Local PHP Security Checker](https://github.com/fabpot/local-php-security-checker). Both of them are open source packages, licensed under the MIT and AGPL licenses respectively, that scan your PHP dependencies for known vulnerabilities using the [Security Advisories Database](https://github.com/FriendsOfPHP/security-advisories).

## References

- [Laravel Documentation on Authentication](https://laravel.com/docs/authentication)
- [Laravel Documentation on Authorization](https://laravel.com/docs/authorization)
- [Laravel Documentation on CSRF](https://laravel.com/docs/csrf)
- [Laravel Documentation on Validation](https://laravel.com/docs/validation)
- [Enlightn SAST and DAST Tool](https://www.laravel-enlightn.com/)
- [Laravel Enlightn Security Documentation](https://www.laravel-enlightn.com/docs/security/)
