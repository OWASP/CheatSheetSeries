# Introduction

This page intends to provide quick basic .NET security tips for developers.

## The .NET Framework

The .NET Framework is Microsoft's principal platform for enterprise development. It is the supporting API for ASP.NET, Windows Desktop applications, Windows Communication Foundation services, SharePoint, Visual Studio Tools for Office and other technologies.

## Updating the Framework

The .NET Framework is kept up-to-date by Microsoft with the Windows Update service. Developers do not normally need to run seperate updates to the Framework. Windows update can be accessed at [Windows Update](http://windowsupdate.microsoft.com/) or from the Windows Update program on a Windows computer.

Individual frameworks can be kept up to date using [NuGet](http://nuget.codeplex.com/wikipage?title=Getting%20Started&referringTitle=Home). As Visual Studio prompts for updates, build it into your lifecycle.

Remember that third-party libraries have to be updated separately and not all of them use NuGet. ELMAH for instance, requires a separate update effort.

# .NET Framework Guidance

The .NET Framework is the set of APIs that support an advanced type system, data, graphics, network, file handling and most of the rest of what is needed to write enterprise apps in the Microsoft ecosystem. It is a nearly ubiquitous library that is strongly named and versioned at the assembly level.

## Data Access

- Use [Parameterized SQL](https://docs.microsoft.com/en-us/dotnet/api/system.data.sqlclient.sqlcommand.prepare?view=netframework-4.7.2) commands for all data access, without exception.
- Do not use [SqlCommand](http://msdn.microsoft.com/en-us/library/system.data.sqlclient.sqlcommand.aspx) with a string parameter made up of a [concatenated SQL String](https://docs.microsoft.com/en-gb/visualstudio/code-quality/ca2100-review-sql-queries-for-security-vulnerabilities?view=vs-2017).
- Whitelist allowable values coming from the user. Use enums, [TryParse](http://msdn.microsoft.com/en-us/library/f02979c7.aspx) or lookup values to assure that the data coming from the user is as expected.
    - Enums are still vulnerable to unexpected values because .NET only validates a successful cast to the underlying data type, integer by default. [Enum.IsDefined](https://msdn.microsoft.com/en-us/library/system.enum.isdefined) can validate whether the input value is valid within the list of defined constants.
- Apply the principle of least privilege when setting up the Database User in your database of choice. The database user should only be able to access items that make sense for the use case.
- Use of the [Entity Framework](http://msdn.microsoft.com/en-us/data/ef.aspx) is a very effective [SQL injection](https://www.owasp.org/index.php/SQL_Injection) prevention mechanism. **Remember that building your own ad hoc queries in Entity Framework is just as susceptible to SQLi as a plain SQL query**.
- When using SQL Server, prefer [integrated authentication](https://docs.microsoft.com/en-us/sql/connect/odbc/linux-mac/using-integrated-authentication?view=sql-server-2017) over [SQL authentication](https://docs.microsoft.com/en-us/sql/relational-databases/security/choose-an-authentication-mode?view=sql-server-2017#connecting-through-sql-server-authentication).
- Use [Always Encrypted](https://msdn.microsoft.com/en-us/library/mt163865.aspx) where possible for sensitive data (SQL Server 2016 and SQL Azure),

## Encryption

- **Never, ever write your own encryption.**
- Use the [Windows Data Protection API (DPAPI)](http://msdn.microsoft.com/en-us/library/ms995355.aspx) for secure local storage of sensitive data.
- Use a strong hash algorithm.
    - In .NET (both Framework and Core) the strongest hashing algorithm for general hashing requirements is [System.Security.Cryptography.SHA512](http://msdn.microsoft.com/en-us/library/system.security.cryptography.sha512.aspx).
    - In the .NET framework the strongest algorithm for password hashing is PBKDF2, implemented as [System.Security.Cryptography.Rfc2898DeriveBytes](http://msdn.microsoft.com/en-us/library/system.security.cryptography.rfc2898derivebytes(v=vs.110).aspx).
    - In .NET Core the strongest algorithm for password hashing is PBKDF2, implemented as [Microsoft.AspNetCore.Cryptography.KeyDerivation.Pbkdf2](https://docs.microsoft.com/en-us/aspnet/core/security/data-protection/consumer-apis/password-hashing) which has several significant advantages over `Rfc2898DeriveBytes`.
    - When using a hashing function to hash non-unique inputs such as passwords, use a salt value added to the original value before hashing.
- Make sure your application or protocol can easily support a future change of cryptographic algorithms.
- Use [Nuget](https://docs.microsoft.com/en-us/nuget/) to keep all of your packages up to date. Watch the updates on your development setup, and plan updates to your applications accordingly.

## General

- Lock down the config file.
    - Remove all aspects of configuration that are not in use.
    - Encrypt sensitive parts of the `web.config` using `aspnet_regiis -pe` ([command line help](https://docs.microsoft.com/en-us/previous-versions/dotnet/netframework-2.0/k6h9cz8h(v=vs.80))).
- For Click Once applications the .Net Framework should be upgraded to use version `4.6.2` to ensure `TLS 1.1/1.2` support.

# ASP NET Web Forms Guidance

ASP.NET Web Forms is the original browser-based application development API for the .NET framework, and is still the most common enterprise platform for web application development.

- Always use [HTTPS](http://support.microsoft.com/kb/324069).
- Enable [requireSSL](http://msdn.microsoft.com/en-us/library/system.web.configuration.httpcookiessection.requiressl.aspx) on cookies and form elements and [HttpOnly](http://msdn.microsoft.com/en-us/library/system.web.configuration.httpcookiessection.httponlycookies.aspx) on cookies in the web.config.
- Implement [customErrors](https://msdn.microsoft.com/en-us/data/h0hfz6fc(v=vs.110)).
- Make sure [tracing](http://www.iis.net/configreference/system.webserver/tracing) is turned off.
- While viewstate isn't always appropriate for web development, using it can provide CSRF mitigation. To make the ViewState protect against CSRF attacks you need to set the [ViewStateUserKey](http://msdn.microsoft.com/en-us/library/ms972969.aspx#securitybarriers_topic2):

```csharp
protected override OnInit(EventArgs e) {
    base.OnInit(e); 
    ViewStateUserKey = Session.SessionID;
} 
```

If you don't use Viewstate, then look to the default master page of the ASP.NET Web Forms default template for a manual anti-CSRF token using a double-submit cookie.

```csharp
private const string AntiXsrfTokenKey = "__AntiXsrfToken";
private const string AntiXsrfUserNameKey = "__AntiXsrfUserName";
private string _antiXsrfTokenValue;
protected void Page_Init(object sender, EventArgs e)
{
    // The code below helps to protect against XSRF attacks
    var requestCookie = Request.Cookies[AntiXsrfTokenKey];
    Guid requestCookieGuidValue;
    if (requestCookie != null && Guid.TryParse(requestCookie.Value, out requestCookieGuidValue))
    {
       // Use the Anti-XSRF token from the cookie
       _antiXsrfTokenValue = requestCookie.Value;
       Page.ViewStateUserKey = _antiXsrfTokenValue;
    }
    else
    {
       // Generate a new Anti-XSRF token and save to the cookie
       _antiXsrfTokenValue = Guid.NewGuid().ToString("N");
       Page.ViewStateUserKey = _antiXsrfTokenValue;
       var responseCookie = new HttpCookie(AntiXsrfTokenKey)
       {
          HttpOnly = true,
          Value = _antiXsrfTokenValue
       };
       if (FormsAuthentication.RequireSSL && Request.IsSecureConnection)
       {
          responseCookie.Secure = true;
       }
       Response.Cookies.Set(responseCookie);
    }
    Page.PreLoad += master_Page_PreLoad;
}
protected void master_Page_PreLoad(object sender, EventArgs e)
{
    if (!IsPostBack)
    {
       // Set Anti-XSRF token
       ViewState[AntiXsrfTokenKey] = Page.ViewStateUserKey;
       ViewState[AntiXsrfUserNameKey] = Context.User.Identity.Name ?? String.Empty;
    }
    else
    {
       // Validate the Anti-XSRF token

if ((string)ViewState[AntiXsrfTokenKey] != _antiXsrfTokenValue ||
          (string)ViewState[AntiXsrfUserNameKey] != (Context.User.Identity.Name ?? String.Empty))
       {
          throw new InvalidOperationException("Validation of Anti-XSRF token failed.");
       }
    }
}
```

- Consider [HSTS](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security) in IIS. See [here](https://support.microsoft.com/en-us/help/954002/how-to-add-a-custom-http-response-header-to-a-web-site-that-is-hosted) for the procedure.
- This is a recommended `web.config` setup that handles HSTS among other things.

```xml
<?xml version="1.0" encoding="UTF-8"?>
 <configuration>
   <system.web>
     <httpRuntime enableVersionHeader="false"/>
   </system.web>
   <system.webServer>
     <security>
       <requestFiltering removeServerHeader="true" />
     </security>
     <staticContent>
       <clientCache cacheControlCustom="public" 
            cacheControlMode="UseMaxAge"    
            cacheControlMaxAge="1.00:00:00" 
            setEtag="true" />
     </staticContent>
     <httpProtocol>
       <customHeaders>
         <add name="Content-Security-Policy" 
            value="default-src 'none'; style-src 'self'; img-src 'self'; font-src 'self'" />
         <add name="X-Content-Type-Options" value="NOSNIFF" />
         <add name="X-Frame-Options" value="DENY" />
         <add name="X-Permitted-Cross-Domain-Policies" value="master-only"/>
         <add name="X-XSS-Protection" value="1; mode=block"/>
         <remove name="X-Powered-By"/>
       </customHeaders>
     </httpProtocol>
     <rewrite>
       <rules>
         <rule name="Redirect to https">
           <match url="(.*)"/>
           <conditions>
             <add input="{HTTPS}" pattern="Off"/>
             <add input="{REQUEST_METHOD}" pattern="^get$|^head$" />
           </conditions>
           <action type="Redirect" url="https://{HTTP_HOST}/{R:1}" redirectType="Permanent"/>
         </rule>
       </rules>
       <outboundRules>
         <rule name="Add HSTS Header" enabled="true">
           <match serverVariable="RESPONSE_Strict_Transport_Security" pattern=".*" />
           <conditions>
             <add input="{HTTPS}" pattern="on" ignoreCase="true" />
           </conditions>
           <action type="Rewrite" value="max-age=15768000" />
         </rule>
       </outboundRules>
     </rewrite>
   </system.webServer>
 </configuration>
```

- Remove the version header.

```xml
<httpRuntime enableVersionHeader="false" />
```

- Also remove the Server header.

```csharp
HttpContext.Current.Response.Headers.Remove("Server");
```

## HTTP validation and encoding

- Do not disable [validateRequest](http://www.asp.net/whitepapers/request-validation) in the `web.config` or the page setup. This value enables limited XSS protection in ASP.NET and should be left intact as it provides partial prevention of Cross Site Scripting. Complete request validation is recommended in addition to the built in protections.
- The 4.5 version of the .NET Frameworks includes the [AntiXssEncoder](https://docs.microsoft.com/en-us/dotnet/api/system.web.security.antixss.antixssencoder?view=netframework-4.7.2) library, which has a comprehensive input encoding library for the prevention of XSS. Use it.
- Whitelist allowable values anytime user input is accepted.
- Validate the URI format using [Uri.IsWellFormedUriString](http://msdn.microsoft.com/en-us/library/system.uri.iswellformeduristring.aspx).

## Forms authentication

- Use cookies for persistence when possible. `Cookieless` auth will default to [UseDeviceProfile](https://docs.microsoft.com/en-us/dotnet/api/system.web.httpcookiemode?view=netframework-4.7.2).
- Don't trust the URI of the request for persistence of the session or authorization. It can be easily faked.
- Reduce the forms authentication timeout from the default of *20 minutes* to the shortest period appropriate for your application. If [slidingExpiration](https://docs.microsoft.com/en-us/dotnet/api/system.web.security.formsauthentication.slidingexpiration?view=netframework-4.7.2) is used this timeout resets after each request, so active users won't be affected.
-   If HTTPS is not used, [slidingExpiration](https://docs.microsoft.com/en-us/dotnet/api/system.web.security.formsauthentication.slidingexpiration?view=netframework-4.7.2) should be disabled. Consider disabling [slidingExpiration](https://docs.microsoft.com/en-us/dotnet/api/system.web.security.formsauthentication.slidingexpiration?view=netframework-4.7.2) even with HTTPS.
- Always implement proper access controls.
    - Compare user provided username with `User.Identity.Name`.
    - Check roles against `User.Identity.IsInRole`.
- Use the [ASP.NET Membership provider and role provider](https://docs.microsoft.com/en-us/dotnet/framework/wcf/samples/membership-and-role-provider), but review the password storage. The default storage hashes the password with a single iteration of SHA-1 which is rather weak. The ASP.NET MVC4 template uses [ASP.NET Identity](http://www.asp.net/identity/overview/getting-started/introduction-to-aspnet-identity) instead of ASP.NET Membership, and ASP.NET Identity uses PBKDF2 by default which is better. Review the OWASP [Password Storage Cheat Sheet](Password_Storage_Cheat_Sheet.md) for more information.
- Explicitly authorize resource requests.
- Leverage role based authorization using `User.Identity.IsInRole`.

# ASP NET MVC Guidance

ASP.NET MVC (Model–View–Controller) is a contemporary web application framework that uses more standardized HTTP communication than the Web Forms postback model. 

The OWASP Top 10 2017 lists the most prevalent and dangerous threats to web security in the world today and is reviewed every 3 years. 

This section is based on this. Your approach to securing your web application should be to start at the top threat A1 below and work down, this will ensure that any time spent on security will be spent most effectively spent and cover the top threats first and lesser threats afterwards. After covering the top 10 it is generally advisable to assess for other threats or get a professionally completed Penetration Test.

## A1 Injection

### SQL Injection

DO: Using an object relational mapper (ORM) or stored procedures is the most effective way of countering the SQL Injection vulnerability.

DO: Use parameterized queries where a direct sql query must be used.

e.g. In entity frameworks:

```sql
var sql = @"Update [User] SET FirstName = @FirstName WHERE Id = @Id";
context.Database.ExecuteSqlCommand(
    sql,
    new SqlParameter("@FirstName", firstname),
    new SqlParameter("@Id", id));
```

DO NOT: Concatenate strings anywhere in your code and execute them against your database (Known as dynamic sql). 

NB: You can still accidentally do this with ORMs or Stored procedures so check everywhere.

e.g

```sql 
string strQry = "SELECT * FROM Users WHERE UserName='" + txtUser.Text + "' AND Password='" 
                + txtPassword.Text + "'";
EXEC strQry // SQL Injection vulnerability!
```

DO: Practise Least Privilege - Connect to the database using an account with a minimum set of permissions required to do it's job i.e. not the sa account

### [OS Injection](https://github.com/OWASP/CheatSheetSeries/blob/master/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.md)

DO: Use [System.Diagnostics.Process.Start](https://docs.microsoft.com/en-us/dotnet/api/system.diagnostics.process.start?view=netframework-4.7.2) to call underlying OS functions.

e.g
``` csharp
System.Diagnostics.Process process = new System.Diagnostics.Process();
System.Diagnostics.ProcessStartInfo startInfo = new System.Diagnostics.ProcessStartInfo();
startInfo.FileName = "validatedCommand";
startInfo.Arguments = "validatedArg1 validatedArg2 validatedArg3";
process.StartInfo = startInfo;
process.Start();
```

DO: Use whitelist validation on all user supplied input. Input validation prevents improperly formed data from entering an information system. For more information please see the [Input Validation Cheat Sheet](Input_Validation_Cheat_Sheet.md).

e.g Validating user input using Regex (IP Address)

``` csharp
//User input
string address = "127.0.0.1";
//Match pattern for IP address    
string Pattern = @"^([1-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])(\.([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])){3}$";    
//Regular Expression object    
Regex check = new Regex(Pattern);    
 
//check to make sure an ip address was provided    
if (string.IsNullOrEmpty(address))    
    //returns false if IP is not provided    
    ...    
else    
    //Matching the pattern
    ...
 ```
 
### LDAP injection

Almost any characters can be used in Distinguished Names. However, some must be escaped with the backslash "\" escape character. Active Directory requires that the following characters be escaped:

| Character | Escape character |
|-----------|:-----:|
|Comma	|,|
|Backslash character|\|
|Pound sign (hash sign)|#|
|Plus sign|+|
|Less than symbol|<|
|Greater than symbol|>|
|Semicolon|;|
|Double quote (quotation mark)|"|
|Equal sign|=|
|Leading or trailing spaces| | 

NB: The space character must be escaped only if it is the leading or trailing character in a component name, such as a Common Name. Embedded spaces should not be escaped.

## A2 Broken Authentication

DO: Use [ASP.net Core Identity](https://docs.microsoft.com/en-us/aspnet/core/security/authentication/identity?view=aspnetcore-2.2&).
ASP.net Core Identity framework is well configured by default, where it uses secure password hashes and an individual salt. Identity uses the PBKDF2 hashing function for passwords, and they generate a random salt per user.

DO: Set secure password policy

e.g ASP.net Core Identity 

``` csharp
//startup.cs
services.Configure<IdentityOptions>(options =>
{
	// Password settings
	options.Password.RequireDigit = true;
	options.Password.RequiredLength = 8;
	options.Password.RequireNonAlphanumeric = true;
	options.Password.RequireUppercase = true;
	options.Password.RequireLowercase = true;
	options.Password.RequiredUniqueChars = 6;
 
 
	options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(30);
	options.Lockout.MaxFailedAccessAttempts = 3;
 
	options.SignIn.RequireConfirmedEmail = true;
	
	options.User.RequireUniqueEmail = true;
});
```
DO: Set a cookie policy

e.g 
``` csharp
//startup.cs
services.ConfigureApplicationCookie(options =>
{
	options.Cookie.HttpOnly = true;
	options.Cookie.Expiration = TimeSpan.FromHours(1)
	options.SlidingExpiration = true;
});
```
## A3 Sensitive Data Exposure

DO NOT: Store encrypted passwords.

DO: Use a strong hash to store password credentials. Use Argon2, PBKDF2, BCrypt or SCrypt with at least 8000 iterations and a strong key.

DO: Enforce passwords with a minimum complexity that will survive a dictionary attack i.e. longer passwords that use the full character set (numbers, symbols and letters) to increase the entropy.

DO: Use a strong encryption routine such as AES-512 where personally identifiable data needs to be restored to it's original format. Do not encrypt passwords. Protect encryption keys more than any other asset. Apply the following test: Would you be happy leaving the data on a spreadsheet on a bus for everyone to read. Assume the attacker can get direct access to your database and protect it accordingly.

DO: Use TLS 1.2 for your entire site. Get a free certificate [LetsEncrypt.org](https://letsencrypt.org/).

DO NOT: [Allow SSL, this is now obsolete](https://github.com/ssllabs/research/wiki/SSL-and-TLS-Deployment-Best-Practices#22-use-secure-protocols).

DO: Have a strong TLS policy (see [SSL Best Practises](http://www.ssllabs.com/projects/best-practises/)), use TLS 1.2 wherever possible. Then check the configuration using [SSL Test](https://www.ssllabs.com/ssltest/) or [TestSSL](https://testssl.sh/).

DO: Ensure headers are not disclosing information about your application. See [HttpHeaders.cs](https://github.com/johnstaveley/SecurityEssentials/blob/master/SecurityEssentials/Core/HttpHeaders.cs) , [Dionach StripHeaders](https://github.com/Dionach/StripHeaders/), disable via `web.config` or [startup.cs](https://medium.com/bugbountywriteup/security-headers-1c770105940b):

e.g Web.config
```xml
<system.web>
    <httpRuntime enableVersionHeader="false"/>
</system.web>
<system.webServer>
    <security>
        <requestFiltering removeServerHeader="true" />
    </security>
    <httpProtocol>
        <customHeaders>
            <add name="X-Content-Type-Options" value="nosniff" />
            <add name="X-Frame-Options" value="DENY" />
            <add name="X-Permitted-Cross-Domain-Policies" value="master-only"/>
            <add name="X-XSS-Protection" value="1; mode=block"/>
            <remove name="X-Powered-By"/>
        </customHeaders>
    </httpProtocol>
</system.webServer>    
```
e.g Startup.cs
``` csharp
app.UseHsts(hsts => hsts.MaxAge(365).IncludeSubdomains());
app.UseXContentTypeOptions();
app.UseReferrerPolicy(opts => opts.NoReferrer());
app.UseXXssProtection(options => options.EnabledWithBlockMode());
app.UseXfo(options => options.Deny());

app.UseCsp(opts => opts
 .BlockAllMixedContent()
 .StyleSources(s => s.Self())
 .StyleSources(s => s.UnsafeInline())
 .FontSources(s => s.Self())
 .FormActions(s => s.Self())
 .FrameAncestors(s => s.Self())
 .ImageSources(s => s.Self())
 .ScriptSources(s => s.Self())
 );
```
For more information about headers can be found [here](https://www.owasp.org/index.php/OWASP_Secure_Headers_Project#xpcdp).

## A4 XML External Entities (XXE)

The following information for XXE injection in .NET is directly from this [web application of unit tests by Dean Fleming](https://github.com/deanf1/dotnet-security-unit-tests).

This web application covers all currently supported .NET XML parsers, and has test cases for each demonstrating when they are safe from XXE injection and when they are not.

Previously, this information was based on [James Jardine's excellent .NET XXE article](https://www.jardinesoftware.net/2016/05/26/xxe-and-net/).

It originally provided more recent and more detailed information than the older article from [Microsoft on how to prevent XXE and XML Denial of Service in .NET](http://msdn.microsoft.com/en-us/magazine/ee335713.aspx), however, it has some inaccuracies that the web application covers.

The following table lists all supported .NET XML parsers and their default safety levels:

| XML Parser            | Safe by default? |
|-----------------------|:----------------:|
| LINQ to XML           | Yes              |
| XmlDictionaryReader   | Yes              |
| XmlDocument           |                  |
| ...prior to 4.5.2     | No               |
| ...in versions 4.5.2+ | Yes              |
| XmlNodeReader         | Yes              |
| XmlReader             | Yes              |
| XmlTextReader         |                  |
| ...prior to 4.5.2     | No               |
| ...in versions 4.5.2+ | Yes              |
| XPathNavigator        |                  |
| ...prior to 4.5.2     | No               |
| ...in versions 4.5.2+ | Yes              |
| XslCompiledTransform  | Yes              |

### LINQ to XML

Both the `XElement` and `XDocument` objects in the `System.Xml.Linq` library are safe from XXE injection by default. `XElement` parses only the elements within the XML file, so DTDs are ignored altogether. `XDocument` has DTDs [disabled by default](https://github.com/dotnet/docs/blob/master/docs/visual-basic/programming-guide/concepts/linq/linq-to-xml-security.md), and is only unsafe if constructed with a different unsafe XML parser.

### XmlDictionaryReader

`System.Xml.XmlDictionaryReader` is safe by default, as when it attempts to parse the DTD, the compiler throws an exception saying that "CData elements not valid at top level of an XML document". It becomes unsafe if constructed with a different unsafe XML parser.

### XmlDocument

Prior to .NET Framework version 4.5.2, `System.Xml.XmlDocument` is **unsafe** by default. The `XmlDocument` object has an `XmlResolver` object within it that needs to be set to null in versions prior to 4.5.2. In versions 4.5.2 and up, this `XmlResolver` is set to null by default.

The following example shows how it is made safe:

``` csharp
 static void LoadXML()
 {
   string xxePayload = "<!DOCTYPE doc [<!ENTITY win SYSTEM 'file:///C:/Users/testdata2.txt'>]>" 
                     + "<doc>&win;</doc>";
   string xml = "<?xml version='1.0' ?>" + xxePayload;

   XmlDocument xmlDoc = new XmlDocument();
   // Setting this to NULL disables DTDs - Its NOT null by default.
   xmlDoc.XmlResolver = null;   
   xmlDoc.LoadXml(xml);
   Console.WriteLine(xmlDoc.InnerText);
   Console.ReadLine();
 }
```

`XmlDocument` can become unsafe if you create your own nonnull `XmlResolver` with default or unsafe settings. If you need to enable DTD processing, instructions on how to do so safely are described in detail in the [referenced MSDN article](https://msdn.microsoft.com/en-us/magazine/ee335713.aspx).

### XmlNodeReader

`System.Xml.XmlNodeReader` objects are safe by default and will ignore DTDs even when constructed with an unsafe parser or wrapped in another unsafe parser.

### XmlReader

`System.Xml.XmlReader` objects are safe by default.

They are set by default to have their ProhibitDtd property set to false in .NET Framework versions 4.0 and earlier, or their `DtdProcessing` property set to Prohibit in .NET versions 4.0 and later.

Additionally, in .NET versions 4.5.2 and later, the `XmlReaderSettings` belonging to the `XmlReader` has its `XmlResolver` set to null by default, which provides an additional layer of safety.

Therefore, `XmlReader` objects will only become unsafe in version 4.5.2 and up if both the `DtdProcessing` property is set to Parse and the `XmlReaderSetting`'s `XmlResolver` is set to a nonnull XmlResolver with default or unsafe settings. If you need to enable DTD processing, instructions on how to do so safely are described in detail in the [referenced MSDN article](https://msdn.microsoft.com/en-us/magazine/ee335713.aspx).

### XmlTextReader

`System.Xml.XmlTextReader` is **unsafe** by default in .NET Framework versions prior to 4.5.2. Here is how to make it safe in various .NET versions:

#### Prior to .NET 4.0

In .NET Framework versions prior to 4.0, DTD parsing behavior for `XmlReader` objects like `XmlTextReader` are controlled by the Boolean `ProhibitDtd` property found in the `System.Xml.XmlReaderSettings` and `System.Xml.XmlTextReader` classes.

Set these values to true to disable inline DTDs completely.

``` csharp
XmlTextReader reader = new XmlTextReader(stream);
// NEEDED because the default is FALSE!!
reader.ProhibitDtd = true;  
```

#### .NET 4.0 - .NET 4.5.2

In .NET Framework version 4.0, DTD parsing behavior has been changed. The `ProhibitDtd` property has been deprecated in favor of the new `DtdProcessing` property.

However, they didn't change the default settings so `XmlTextReader` is still vulnerable to XXE by default.

Setting `DtdProcessing` to `Prohibit` causes the runtime to throw an exception if a `<!DOCTYPE>` element is present in the XML.

To set this value yourself, it looks like this:

``` csharp
XmlTextReader reader = new XmlTextReader(stream);
// NEEDED because the default is Parse!!
reader.DtdProcessing = DtdProcessing.Prohibit;  
```

Alternatively, you can set the `DtdProcessing` property to `Ignore`, which will not throw an exception on encountering a `<!DOCTYPE>` element but will simply skip over it and not process it. Finally, you can set `DtdProcessing` to `Parse` if you do want to allow and process inline DTDs.

### .NET 4.5.2 and later

In .NET Framework versions 4.5.2 and up, `XmlTextReader`'s internal `XmlResolver` is set to null by default, making the `XmlTextReader` ignore DTDs by default. The `XmlTextReader` can become unsafe if if you create your own nonnull `XmlResolver` with default or unsafe settings.

### XPathNavigator

`System.Xml.XPath.XPathNavigator` is **unsafe** by default in .NET Framework versions prior to 4.5.2.

This is due to the fact that it implements `IXPathNavigable` objects like `XmlDocument`, which are also unsafe by default in versions prior to 4.5.2.

You can make `XPathNavigator` safe by giving it a safe parser like `XmlReader` (which is safe by default) in the `XPathDocument`'s constructor.

Here is an example:

``` csharp
XmlReader reader = XmlReader.Create("example.xml");
XPathDocument doc = new XPathDocument(reader);
XPathNavigator nav = doc.CreateNavigator();
string xml = nav.InnerXml.ToString();
```

### XslCompiledTransform

`System.Xml.Xsl.XslCompiledTransform` (an XML transformer) is safe by default as long as the parser it’s given is safe.

It is safe by default because the default parser of the `Transform()` methods is an `XmlReader`, which is safe by default (per above).

[The source code for this method is here.](http://www.dotnetframework.org/default.aspx/4@0/4@0/DEVDIV_TFS/Dev10/Releases/RTMRel/ndp/fx/src/Xml/System/Xml/Xslt/XslCompiledTransform@cs/1305376/XslCompiledTransform@cs)

Some of the `Transform()` methods accept an `XmlReader` or `IXPathNavigable` (e.g., `XmlDocument`) as an input, and if you pass in an unsafe XML Parser then the `Transform` will also be unsafe.

## A5 Broken Access Control

### Weak Account management

Ensure cookies are sent via httpOnly:

```csharp
CookieHttpOnly = true,
```

Reduce the time period a session can be stolen in by reducing session timeout and removing sliding expiration:

```csharp
ExpireTimeSpan = TimeSpan.FromMinutes(60),
SlidingExpiration = false
```

See [here](https://github.com/johnstaveley/SecurityEssentials/blob/master/SecurityEssentials/App_Start/Startup.Auth.cs) for full startup code snippet

Ensure cookie is sent over https in the production environment. This should be enforced in the config transforms:

```xml
<httpCookies requireSSL="true" xdt:Transform="SetAttributes(requireSSL)"/>
<authentication>
    <forms requireSSL="true" xdt:Transform="SetAttributes(requireSSL)"/>
</authentication>
```

Protect LogOn, Registration and password reset methods against brute force attacks by throttling requests (see code below), consider also using ReCaptcha.

```csharp
[HttpPost]
[AllowAnonymous]
[ValidateAntiForgeryToken]
[AllowXRequestsEveryXSecondsAttribute(Name = "LogOn", 
Message = "You have performed this action more than {x} times in the last {n} seconds.", 
Requests = 3, Seconds = 60)]
public async Task<ActionResult> LogOn(LogOnViewModel model, string returnUrl)
```

DO NOT: Roll your own authentication or session management, use the one provided by .Net

DO NOT: Tell someone if the account exists on LogOn, Registration or Password reset. Say something like 'Either the username or password was incorrect', or 'If this account exists then a reset token will be sent to the registered email address'. This protects against account enumeration. 

The feedback to the user should be identical whether or not the account exists, both in terms of content and behaviour: e.g. if the response takes 50% longer when the account is real then membership information can be guessed and tested.

### Missing function-level access control

DO: Authorize users on all externally facing endpoints. The .NET framework has many ways to authorize a user, use them at method level:

```csharp
[Authorize(Roles = "Admin")]
[HttpGet]
public ActionResult Index(int page = 1)
```

or better yet, at controller level:

```csharp
[Authorize]
public class UserController
```

You can also check roles in code using identity features in .net: `System.Web.Security.Roles.IsUserInRole(userName, roleName)`

### Insecure Direct object references

When you have a resource (object) which can be accessed by a reference (in the sample below this is the `id`) then you need to ensure that the user is intended to be there

```csharp
// Insecure
public ActionResult Edit(int id)
{
  var user = _context.Users.FirstOrDefault(e => e.Id == id);
  return View("Details", new UserViewModel(user);
}

// Secure
public ActionResult Edit(int id)
{
  var user = _context.Users.FirstOrDefault(e => e.Id == id);
  // Establish user has right to edit the details
  if (user.Id != _userIdentity.GetUserId())
  {
        HandleErrorInfo error = new HandleErrorInfo(
            new Exception("INFO: You do not have permission to edit these details"));
        return View("Error", error);
  }
  return View("Edit", new UserViewModel(user);
}
```
## A6 Security Misconfiguration

### Debug and Stack Trace
Ensure debug and trace are off in production. This can be enforced using web.config transforms:

```xml
<compilation xdt:Transform="RemoveAttributes(debug)" />
<trace enabled="false" xdt:Transform="Replace"/>
```

DO NOT: Use default passwords

DO: (When using TLS) Redirect a request made over Http to https:

e.g Global.asax.cs
```csharp
protected void Application_BeginRequest()
{
    #if !DEBUG
    // SECURE: Ensure any request is returned over SSL/TLS in production
    if (!Request.IsLocal && !Context.Request.IsSecureConnection) {
        var redirect = Context.Request.Url.ToString()
                        .ToLower(CultureInfo.CurrentCulture)
                        .Replace("http:", "https:");
        Response.Redirect(redirect);
    }
    #endif
}
```
e.g Startup.cs in the Configure()

``` csharp
  app.UseHttpsRedirection();
```
### Cross-site request forgery

DO: Send the anti-forgery token with every POST/PUT request:

```csharp
using (Html.BeginForm("LogOff", "Account", FormMethod.Post, new { id = "logoutForm", 
                        @class = "pull-right" }))
{
    @Html.AntiForgeryToken()
    <ul class="nav nav-pills">
        <li role="presentation">
        Logged on as @User.Identity.Name
        </li>
        <li role="presentation">
        <a href="javascript:document.getElementById('logoutForm').submit()">Log off</a>
        </li>
    </ul>
}
```

Then validate it at the method or preferably the controller level:

```csharp
[HttpPost]
[ValidateAntiForgeryToken]
public ActionResult LogOff()
```

Make sure the tokens are removed completely for invalidation on logout.

```csharp
/// <summary>
/// SECURE: Remove any remaining cookies including Anti-CSRF cookie
/// </summary>
public void RemoveAntiForgeryCookie(Controller controller)
{
    string[] allCookies = controller.Request.Cookies.AllKeys;
    foreach (string cookie in allCookies)
    {
        if (controller.Response.Cookies[cookie] != null && 
            cookie == "__RequestVerificationToken")
        {
            controller.Response.Cookies[cookie].Expires = DateTime.Now.AddDays(-1);
        }
    }
}
```

NB: You will need to attach the anti-forgery token to Ajax requests.

After .NET Core 2.0 it is possible to automatically generate and verify the antiforgery token. Forms must have the requisite helper as seen here:

```html
<form action="RelevantAction" >
@Html.AntiForgeryToken()
</form>
```

And then add the `[AutoValidateAntiforgeryToken]` attribute to the action result.

## A7 Cross-Site Scripting (XSS)

DO NOT: Trust any data the user sends you, prefer white lists (always safe) over black lists

You get encoding of all HTML content with MVC3, to properly encode all content whether HTML, javascript, CSS, LDAP etc use the Microsoft AntiXSS library:

`Install-Package AntiXSS`

Then set in config:

```xml
<system.web>
<httpRuntime targetFramework="4.5" 
enableVersionHeader="false" 
encoderType="Microsoft.Security.Application.AntiXssEncoder, AntiXssLibrary" 
maxRequestLength="4096" />
```

DO NOT: Use the `[AllowHTML]` attribute or helper class `@Html.Raw` unless you really know that the content you are writing to the browser is safe and has been escaped properly.

DO: Enable a [Content Security Policy](https://developers.google.com/web/fundamentals/security/csp/), this will prevent your pages from accessing assets it should not be able to access (e.g. a malicious script):

```xml
<system.webServer>
    <httpProtocol>
        <customHeaders>
            <add name="Content-Security-Policy" 
                value="default-src 'none'; style-src 'self'; img-src 'self'; 
                font-src 'self'; script-src 'self'" />
```


## A8 Insecure Deserialization
DO NOT: Accept Serialized Objects from Untrusted Sources

DO: Prevent Deserialization of Domain Objects

DO: The Serialization Process Needs to Be Encrypted So That Hostile Object Creation and Data Tampering Cannot Run

DO: Run the Deserialization Code with Limited Access Permissions
If a desterilized hostile object tries to initiate a system processes or access a resource within the server or the host’s OS, it will be denied access and a permission flag will be raised so that a system administrator is made aware of any anomalous activity on the server. 

DO: Validate User Input
Malicious users are able to use objects like cookies to insert malicious information to change user roles. In some cases, hackers are able to elevate their privileges to administrator rights by using a pre-existing or cached password hash from a previous session. 

### WhiteBox Review

Search the source code for the following terms:

1.  `TypeNameHandling`
2.  `JavaScriptTypeResolver`

Look for any serializers where the type is set by a user controlled variable.

### BlackBox Review

Search for the following base64 encoded content that starts with:

```
AAEAAAD/////
```

Search for content with the following text:

1. `TypeObject`
2.  `$type:`

### General Precautions

Don't allow the datastream to define the type of object that the stream will be deserialized to. You can prevent this by for example using the `DataContractSerializer` or `XmlSerializer` if at all possible.

Where `JSON.Net` is being used make sure the `TypeNameHandling` is only set to `None`.

```csharp
TypeNameHandling = TypeNameHandling.None
```

If `JavaScriptSerializer` is to be used then do not use it with a `JavaScriptTypeResolver`.

If you must deserialise data streams that define their own type, then restrict the types that are allowed to be deserialized. One should be aware that this is still risky as many native .Net types potentially dangerous in themselves. e.g.

```csharp
System.IO.FileInfo
```    

`FileInfo` objects that reference files actually on the server can when deserialized, change the properties of those files e.g. to read-only, creating a potential denial of service attack.

Even if you have limited the types that can be deserialised remember that some types have properties that are risky. `System.ComponentModel.DataAnnotations.ValidationException`, for example has a property `Value` of type `Object`. if this type is the type allowed for deserialization then an attacker can set the `Value` property to any object type they choose.

Attackers should be prevented from steering the type that will be instantiated. If this is possible then even `DataContractSerializer` or `XmlSerializer` can be subverted e.g.

```csharp
// Action below is dangerous if the attacker can change the data in the database
var typename = GetTransactionTypeFromDatabase();  

var serializer = new DataContractJsonSerializer(Type.GetType(typename));

var obj = serializer.ReadObject(ms);
```    

Execution can occur within certain .Net types during deserialization. Creating a control such as the one shown below is ineffective.

```csharp
var suspectObject = myBinaryFormatter.Deserialize(untrustedData);

//Check below is too late! Execution may have already occurred.
if (suspectObject is SomeDangerousObjectType) 
{
    //generate warnings and dispose of suspectObject
}
```    

For `BinaryFormatter` and `JSON.Net` it is possible to create a safer form of white list control useing a custom `SerializationBinder`.

Try to keep up-to-date on known .Net insecure deserialization gadgets and pay special attention where such types can be created by your deserialization processes. **A deserializer can only instantiate types that it knows about**. 

Try to keep any code that might create potential gagdets separate from any code that has internet connectivity. As an example `System.Windows.Data.ObjectDataProvider` used in WPF applications is a known gadget that allows arbitrary method invocation. It would be risky to have this a reference to this assembly in a REST service project that deserializes untrusted data.

### Known .NET RCE Gadgets

- `System.Configuration.Install.AssemblyInstaller`
- `System.Activities.Presentation.WorkflowDesigner`
- `System.Windows.ResourceDictionary`
- `System.Windows.Data.ObjectDataProvider`
- `System.Windows.Forms.BindingSource`
- `Microsoft.Exchange.Management.SystemManager.WinForms.ExchangeSettingsProvider`
- `System.Data.DataViewManager, System.Xml.XmlDocument/XmlDataDocument`
- `System.Management.Automation.PSObject`

More information can be found here: [Deserialization Cheat Sheet](https://github.com/OWASP/CheatSheetSeries/blob/master/cheatsheets/Deserialization_Cheat_Sheet.md)

## A9 Using Components with Known Vulnerabilities

DO: Keep the .Net framework updated with the latest patches

DO: Keep your [NuGet](https://docs.microsoft.com/en-us/nuget/) packages up to date, many will contain their own vulnerabilities.

DO: Run the [OWASP Dependency Checker](https://www.owasp.org/index.php/OWASP_Dependency_Check) against your application as part of your build process and act on any high level vulnerabilities.

## A10 Insufficient Logging & Monitoring

# OWASP 2013
Below is vulnerability not discussed in OWASP 2017

## A10 Unvalidated redirects and forwards

A protection against this was introduced in Mvc 3 template. Here is the code:

```csharp
public async Task<ActionResult> LogOn(LogOnViewModel model, string returnUrl)
{
    if (ModelState.IsValid)
    {
        var logonResult = await _userManager.TryLogOnAsync(model.UserName, model.Password);
        if (logonResult.Success)
        {
            await _userManager.LogOnAsync(logonResult.UserName, model.RememberMe);  
            return RedirectToLocal(returnUrl);
...
```

```csharp
private ActionResult RedirectToLocal(string returnUrl)
{
    if (Url.IsLocalUrl(returnUrl))
    {
        return Redirect(returnUrl);
    }
    else
    {
        return RedirectToAction("Landing", "Account");
    }
}
```

Other advice:

- Protect against Clickjacking and man in the middle attack from capturing an initial Non-TLS request, set the `X-Frame-Options` and `Strict-Transport-Security` (HSTS) headers. Full details [here](https://github.com/johnstaveley/SecurityEssentials/blob/master/SecurityEssentials/Core/HttpHeaders.cs)
- Protect against a man in the middle attack for a user who has never been to your site before. Register for [HSTS preload](https://hstspreload.org/)
- Maintain security testing and analysis on Web API services. They are hidden inside MEV sites, and are public parts of a site that will be found by an attacker. All of the MVC guidance and much of the WCF guidance applies to the Web API.

More information:

For more information on all of the above and code samples incorporated into a sample MVC5 application with an enhanced security baseline go to [Security Essentials Baseline project](http://github.com/johnstaveley/SecurityEssentials/)

# XAML Guidance

- Work within the constraints of Internet Zone security for your application.
- Use ClickOnce deployment. For enhanced permissions, use permission elevation at runtime or trusted application deployment at install time.

# Windows Forms Guidance

- Use partial trust when possible. Partially trusted Windows applications reduce the attack surface of an application. Manage a list of what permissions your app must use, and what it may use, and then make the request for those permissions declaratively at run time.
- Use ClickOnce deployment. For enhanced permissions, use permission elevation at runtime or trusted application deployment at install time.

## WCF Guidance

- Keep in mind that the only safe way to pass a request in RESTful services is via `HTTP POST`, with `TLS enabled`. GETs are visible in the `querystring`, and a lack of TLS means the body can be intercepted.
- Avoid [BasicHttpBinding](https://docs.microsoft.com/en-us/dotnet/api/system.servicemodel.basichttpbinding?view=netframework-4.7.2). It has no default security configuration. Use [WSHttpBinding](https://docs.microsoft.com/en-us/dotnet/api/system.servicemodel.wshttpbinding?view=netframework-4.7.2) instead.
- Use at least two security modes for your binding. Message security includes security provisions in the headers. Transport security means use of SSL. [TransportWithMessageCredential](https://docs.microsoft.com/en-us/dotnet/framework/wcf/samples/ws-transport-with-message-credential) combines the two.
- Test your WCF implementation with a fuzzer like the [ZAP](https://www.owasp.org/index.php/OWASP_Zed_Attack_Proxy_Project).

# Authors and Primary Editors

Bill Sempf - bill.sempf@owasp.org

Troy Hunt - troyhunt@hotmail.com

Jeremy Long - jeremy.long@owasp.org

Shane Murnion

John Staveley

Steve Bamelis

Xander Sherry

Sam Ferree
