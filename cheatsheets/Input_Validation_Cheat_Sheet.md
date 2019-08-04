# Introduction

This article is focused on providing clear, simple, actionable guidance for providing Input Validation security functionality in your applications.

# Goals of Input Validation

Input validation is performed to ensure only properly formed data is entering the workflow in an information system, preventing malformed data from persisting in the database and triggering malfunction of various downstream components. Input validation should happen as early as possible in the data flow, preferably as soon as the data is received from the external party.

Data from all potentially untrusted sources should be subject to input validation, including not only Internet-facing web clients but also backend feeds over extranets, from [suppliers, partners, vendors or regulators](https://badcyber.com/several-polish-banks-hacked-information-stolen-by-unknown-attackers/), each of which may be compromised on their own and start sending malformed data.

Input Validation should not be used as the *primary* method of preventing [XSS](Cross_Site_Scripting_Prevention_Cheat_Sheet.md), [SQL Injection](SQL_Injection_Prevention_Cheat_Sheet.md) and other attacks which are covered in respective [cheat sheets](https://www.owasp.org/index.php/OWASP_Cheat_Sheet_Series) but can significantly contribute to reducing their impact if implemented properly.

# Input validation strategies

Input validation should be applied on both **syntactical** and **Semantic** level. 

**Syntactic** validation should enforce correct syntax of structured fields (e.g. SSN, date, currency symbol).

**Semantic** validation should enforce correctness of their *values* in the specific business context (e.g. start date is before end date, price is within expected range).

It is always recommended to prevent attacks as early as possible in the processing of the user’s (attacker's) request. Input validation can be used to detect unauthorized input before it is processed by the application.

# Implementing input validation

Input validation can be implemented using any programming technique that allows effective enforcement of syntactic and semantic correctness, for example:

- Data type validators available natively in web application frameworks (such as [Django Validators](https://docs.djangoproject.com/en/1.11/ref/validators/), [Apache Commons Validators](https://commons.apache.org/proper/commons-validator/apidocs/org/apache/commons/validator/package-summary.html#doc.Usage.validator) etc).
- Validation against [JSON Schema](http://json-schema.org/) and [XML Schema (XSD)](https://www.w3schools.com/xml/schema_intro.asp) for input in these formats.
- Type conversion (e.g. `Integer.parseInt()` in Java, `int()` in Python) with strict exception handling
- Minimum and maximum value range check for numerical parameters and dates, minimum and maximum length check for strings.
- Array of allowed values for small sets of string parameters (e.g. days of week).
- Regular expressions for any other structured data covering the whole input string `(^...$)` and **not** using "any character" wildcard (such as `.` or `\S`)

## Whitelisting vs blacklisting

It is a common mistake black list validation in order to try to detect possibly dangerous characters and patterns like the apostrophe `'` character, the string `1=1`, or the `<script>` tag, but this is a massively flawed approach as it is trivial for an attacker to avoid getting caught by such filters. 

Plus, such filters frequently prevent authorized input, like `O'Brian`, where the `'` character is fully legitimate. For more information on XSS filter evasion please see the [this wiki page](https://www.owasp.org/index.php/XSS_Filter_Evasion_Cheat_Sheet).

White list validation is appropriate for all input fields provided by the user. White list validation involves defining exactly what IS authorized, and by definition, everything else is not authorized. 

If it's well structured data, like dates, social security numbers, zip codes, e-mail addresses, etc. then the developer should be able to define a very strong validation pattern, usually based on regular expressions, for validating such input. 

If the input field comes from a fixed set of options, like a drop down list or radio buttons, then the input needs to match exactly one of the values offered to the user in the first place.

## Validating free-form Unicode text

Free-form text, especially with Unicode characters, is perceived as difficult to validate due to a relatively large space of characters that need to be whitelisted. 

It's also free-form text input that highlights the importance of proper context-aware output encoding and quite clearly demonstrates that input validation is **not** the primary safeguards against Cross-Site Scripting. If your users want to type apostrophe `'` or less-than sign `<` in their comment field, they might have perfectly legitimate reason for that and the application's job is to properly handle it throughout the whole life cycle of the data.

The primary means of input validation for free-form text input should be:

- **Normalization:** Ensure canonical encoding is used across all the text and no invalid characters are present.
- **Character category whitelisting:** Unicode allows whitelisting categories such as "decimal digits" or "letters" which not only covers the Latin alphabet but also various other scripts used globally (e.g. Arabic, Cyryllic, CJK ideographs etc).
- **Individual character whitelisting:** If you allow letters and ideographs in names and also want to allow apostrophe `'` for Irish names, but don't want to allow the whole punctuation category.

References: 

- [Input validation of free-form Unicode text in Python](https://ipsec.pl/python/2017/input-validation-free-form-unicode-text-python.html)

## Regular expressions

Developing regular expressions can be complicated, and is well beyond the scope of this cheat sheet.

There are lots of resources on the internet about how to write regular expressions, including this [site](https://www.regular-expressions.info/) and the [OWASP Validation Regex Repository](https://www.owasp.org/index.php/OWASP_Validation_Regex_Repository).

In summary, input validation should:

- Be applied to all input data, at minimum.
- Define the allowed set of characters to be accepted.
- Defines a minimum and maximum length for the data (e.g. `{1,25}` ).

# White List Regular Expression Examples

Validating an U.S. Zip Code (5 digits plus optional -4)

```text
^\d{5}(-\d{4})?$
```

Validating U.S. State Selection From a Drop-Down Menu

```text
^(AA|AE|AP|AL|AK|AS|AZ|AR|CA|CO|CT|DE|DC|FM|FL|GA|GU|
HI|ID|IL|IN|IA|KS|KY|LA|ME|MH|MD|MA|MI|MN|MS|MO|MT|NE| 
NV|NH|NJ|NM|NY|NC|ND|MP|OH|OK|OR|PW|PA|PR|RI|SC|SD|TN|
TX|UT|VT|VI|VA|WA|WV|WI|WY)$
```

**Java Regex Usage Example**

Example validating the parameter “zip” using a regular expression.

```java
private static final Pattern zipPattern = Pattern.compile("^\d{5}(-\d{4})?$");

public void doPost( HttpServletRequest request, HttpServletResponse response) {
  try {
      String zipCode = request.getParameter( "zip" );
      if ( !zipPattern.matcher( zipCode ).matches()  {
          throw new YourValidationException( "Improper zipcode format." );
      }
      // do what you want here, after its been validated ..
  } catch(YourValidationException e ) {
      response.sendError( response.SC_BAD_REQUEST, e.getMessage() );
  }
}
```

Some white list validators have also been predefined in various open source packages that you can leverage. For example:

- [Apache Commons Validator](http://commons.apache.org/proper/commons-validator/)

# Client Side vs Server Side Validation

Be aware that any JavaScript input validation performed on the client can be bypassed by an attacker that disables JavaScript or uses a Web Proxy. Ensure that any input validation performed on the client is also performed on the server.

# Validating Rich User Content

It is very difficult to validate rich content submitted by a user. For more information, please see the XSS cheatsheet on [Sanitizing HTML Markup with a Library Designed for the Job](Cross_Site_Scripting_Prevention_Cheat_Sheet.md).

# Preventing XSS and Content Security Policy

All user data controlled must be encoded when returned in the html page to prevent the execution of malicious data (e.g. XSS). For example `<script>` would be returned as `&lt;script&gt;`

The type of encoding is specific to the context of the page where the user controlled data is inserted. For example, HTML entity encoding is appropriate for data placed into the HTML body. However, user data placed into a script would need JavaScript specific output encoding.

Detailed information on XSS prevention here: [OWASP XSS Prevention Cheat Sheet](Cross_Site_Scripting_Prevention_Cheat_Sheet.md)

# File Upload Validation

Many websites allow users to upload files, such as a profile picture or more. This section helps provide that feature securely.

Additional information on upload protection here: [File Upload Protection Cheat Sheet](Protect_FileUpload_Against_Malicious_File.md).

## Upload Verification

- Use input validation to ensure the uploaded filename uses an expected extension type.
- Ensure the uploaded file is not larger than a defined maximum file size.
- If the website supports ZIP file upload, do validation check before unzip the file. The check includes the target path, level of compress, estimated unzip size.

## Upload Storage

- Use a new filename to store the file on the OS. Do not use any user controlled text for this filename or for the temporary filename.
- When the file is uploaded to web, it's suggested to rename the file on storage. For example, the uploaded filename is *test.JPG*, rename it to *JAI1287uaisdjhf.JPG* with a random file name. The purpose of doing it to prevent the risks of direct file access and ambigious filename to evalide the filter, such as `test.jpg;.asp or /../../../../../test.jpg`.
- Uploaded files should be analyzed for malicious content (anti-malware, static analysis, etc).
- The file path should not be able to specify by client side. It's decided by server side.

## Public Serving of Uploaded Content

- Ensure uploaded images are served with the correct content-type (e.g. image/jpeg, application/x-xpinstall)

## Beware of "special" files

The upload feature should be using a whitelist approach to only allow specific file types and extensions. However, it is important to be aware of the following file types that, if allowed, could result in security vulnerabilities:
- **crossdomain.xml** / **clientaccesspolicy.xml:** allows cross-domain data loading in Flash, Java and Silverlight. If permitted on sites with authentication this can permit cross-domain data theft and CSRF attacks. Note this can get pretty complicated depending on the specific plugin version in question, so its best to just prohibit files named "crossdomain.xml" or "clientaccesspolicy.xml".
- **.htaccess** and **.htpasswd:** Provides server configuration options on a per-directory basis, and should not be permitted. See [HTACCESS documentation](http://en.wikipedia.org/wiki/Htaccess).
- Web executable script files are suggested not to be allowed such as `aspx, asp, css, swf, xhtml, rhtml, shtml, jsp, js, pl, php, cgi`.

## Upload Verification

- Use image rewriting libraries to verify the image is valid and to strip away extraneous content.
- Set the extension of the stored image to be a valid image extension based on the detected content type of the image from image processing (e.g. do not just trust the header from the upload).
- Ensure the detected content type of the image is within a list of defined image types (jpg, png, etc)

# Email Address Validation

## Email Validation Basics

Many web applications do not treat email addresses correctly due to common misconceptions about what constitutes a valid address. Specifically, it is completely valid to have an mailbox address which:

- Is case sensitive in the local portion of the address (left of the rightmost `@` character).
- Has non-alphanumeric characters in the local-part (including `+` and `@`).
- Has zero or more labels.

At the time of writing, [RFC 5321](https://tools.ietf.org/html/rfc5321) is the current standard defining SMTP and what constitutes a valid mailbox address. Please note, email addresses should be considered to be public data.

Many web applications contain computationally expensive and inaccurate regular expressions that attempt to validate email addresses. Recent changes to the landscape mean that the number of false-negatives will increase, particularly due to:

- Increased popularity of sub-addressing by providers such as Gmail (commonly using `+` as a token in the local-part to affect delivery)
-  New [gTLDs](https://en.wikipedia.org/wiki/Generic_top-level_domain) with long names (many regular expressions check the number and length of each label in the domain)

Following [RFC 5321](https://tools.ietf.org/html/rfc5321), best practice for validating an email address would be to:

- Check for presence of at least one `@` symbol in the address.
- Ensure the local-part is no longer than **64 octets**.
- Ensure the domain is no longer than **255 octets**.
- Ensure the address **is deliverable**.

Note that [RFC 5321](https://tools.ietf.org/html/rfc5321) allows potentially dangerous characters in email addresses. For example, `"><script>alert(1);</script>"@example.org` is a valid email address. As such, it should not be assumed that strings which are valid email addresses are safe to display unencoded or to include in SQL queries.

To ensure an address is deliverable, the only way to check this is to send the user an email and have the user take action to confirm receipt. Beyond confirming that the email address is valid and deliverable, this also provides a positive acknowledgement that the user has access to the mailbox and is likely to be authorized to use it. 

This does not mean that other users cannot access this mailbox, for example when the user makes use of a service that generates a throw away email address.

- Email verification links should only satisfy the requirement of verify email address ownership and should not provide the user with an authenticated session (e.g. the user must still authenticate as normal to access the application).
- Email verification codes must expire after the first use or expire after 8 hours if not used.

## Address Normalization

As the local-part of email addresses are, in fact - case sensitive, it is important to store and compare email addresses correctly. To normalise an email address input, you would convert the domain part ONLY to lowercase.

Unfortunately this does and will make input harder to normalise and correctly match to a users intent. It is reasonable to only accept one unique capitalisation of an otherwise identical address, however in this case it is critical to:

- Store the user-part as provided and verified by user verification.
- Perform comparisons by `lowercase(provided)==lowercase(persisted)`.
