# XPath Injection Prevention Cheat Sheet

## Introduction

This cheat sheet provides guidance on preventing [XPath injection](https://cwe.mitre.org/data/definitions/643.html) vulnerabilities in applications that use XPath to query XML data. XPath injection occurs when untrusted input is concatenated into XPath expressions, allowing attackers to manipulate query logic and access unauthorized data.

## What is XPath Injection?

[XPath injection](https://cwe.mitre.org/data/definitions/643.html) is a type of injection attack where an attacker can modify XPath queries by injecting malicious input. Similar to SQL injection, XPath injection exploits applications that construct XPath expressions using string concatenation with user-supplied input instead of using parameterized or precompiled queries.

### Attack Consequences

Successful XPath injection attacks can lead to:

- **Authentication bypass:** Manipulating predicates to gain unauthorized access
- **Data extraction:** Accessing sensitive XML data outside the intended scope
- **Application logic bypass:** Altering query conditions to bypass authorization checks
- **Blind data extraction:** Inferring information through response differences
- **XML structure discovery:** Revealing the XML schema through error messages or response variations

### Common Vulnerable Patterns

```java
// UNSAFE: String concatenation with user input
String userInput = request.getParameter("username");
String xpathQuery = "//users/user[username='" + userInput + "' and password='" + password + "']";
```

An attacker could input `admin' or '1'='1` to bypass authentication, resulting in:

```xpath
//users/user[username='admin' or '1'='1' and password='...']
```

## Primary Defenses

### Defense Option 1: Parameterized XPath Queries (Recommended)

The most effective defense is to use parameterized XPath queries (XPath variables) when the underlying API supports it. This ensures user input is treated strictly as data, not as part of the query structure.

#### Java Example Using XPath Variables

[Java's XPathVariableResolver](https://docs.oracle.com/en/java/javase/17/docs/api/java.xml/javax/xml/xpath/XPathVariableResolver.html) provides a mechanism to bind variables to XPath expressions:

```java
// Safe: Using XPath variables
String userInput = request.getParameter("username");
String passwordInput = request.getParameter("password");

// Define XPath expression with variables
String xpathExpression = "//users/user[username=$username and password=$password]";

// Create XPath with variable resolver
XPathFactory xPathFactory = XPathFactory.newInstance();
XPath xpath = xPathFactory.newXPath();

// Set up variable resolver
xpath.setXPathVariableResolver(new XPathVariableResolver() {
    @Override
    public Object resolveVariable(QName variableName) {
        if ("username".equals(variableName.getLocalPart())) {
            return userInput;
        } else if ("password".equals(variableName.getLocalPart())) {
            return passwordInput;
        }
        return null;
    }
});

// Compile and evaluate
XPathExpression expr = xpath.compile(xpathExpression);
NodeList result = (NodeList) expr.evaluate(xmlDocument, XPathConstants.NODESET);
```

#### .NET Example Using XPath Variables

```csharp
// Safe: Using XPath variables in .NET
string userInput = Request.QueryString["username"];
string passwordInput = Request.QueryString["password"];

XmlDocument doc = new XmlDocument();
doc.Load("users.xml");

XPathNavigator navigator = doc.CreateNavigator();

// Define XPath with variables
string xpathQuery = "//users/user[username=$username and password=$password]";

XPathExpression expr = navigator.Compile(xpathQuery);

// Create variable context
CustomContext context = new CustomContext();
context.AddVariable("username", userInput);
context.AddVariable("password", passwordInput);

expr.SetContext(context);

XPathNodeIterator iterator = navigator.Select(expr);
```

### Defense Option 2: Precompiled XPath Expressions

When the XPath structure is known at design time, use precompiled XPath expressions and avoid dynamic construction entirely.

```java
// Safe: Precompiled XPath with fixed structure
XPath xpath = XPathFactory.newInstance().newXPath();

// Compile once during initialization
XPathExpression userLookup = xpath.compile("//users/user[@id=$id]");

// Use repeatedly with different variable values
xpath.setXPathVariableResolver(variableName -> {
    if ("id".equals(variableName.getLocalPart())) {
        return sanitizedUserId;  // Still validate input
    }
    return null;
});

NodeList result = (NodeList) userLookup.evaluate(xmlDocument, XPathConstants.NODESET);
```

### Defense Option 3: Input Validation with Allow-Lists

When XPath variables are not supported by the implementation, or when parts of the XPath structure must vary based on user input (such as element names or attribute names), strict input validation is essential.

#### Validation Strategy

1. **Prefer mapping user choices to fixed XPath expressions** rather than allowing direct structural input
2. **Use strict allow-lists** for any structural components that must vary
3. **Reject any input** containing XPath metacharacters when structural variation is required

#### Example: Mapping User Choices to Fixed Queries

```java
// Safe: Map user input to predefined queries
String sortField = request.getParameter("sort");

Map<String, String> allowedSorts = Map.of(
    "name", "//product[category='electronics']",
    "price", "//product[category='electronics']",
    "rating", "//product[category='electronics']"
);

String xpathQuery = allowedSorts.get(sortField);

if (xpathQuery == null) {
    throw new IllegalArgumentException("Invalid sort field");
}

// Append sort logic to the fixed query
// ... additional processing
```

#### Example: Allow-List Validation for Element Names

```java
// Safe: Strict allow-list for element names
String userSelectedField = request.getParameter("field");

// Define allowed field names
Set<String> allowedFields = Set.of("username", "email", "firstName", "lastName");

if (!allowedFields.contains(userSelectedField)) {
    throw new SecurityException("Invalid field name");
}

// Only use validated input in XPath
String xpathQuery = "//user/" + userSelectedField;
```

### Defense Option 4: Escaping (Strongly Discouraged)

Escaping is **not recommended** as a primary defense because:

1. [XPath 1.0](https://www.w3.org/TR/1999/REC-xpath-19991116/) has no built-in escaping mechanism
2. Apostrophes and quotes both delimit strings, making reliable escaping complex
3. Different XPath implementations may handle edge cases inconsistently
4. Future XPath versions may introduce new metacharacters

If escaping is unavoidable (legacy systems with no parameterization support):

```java
// LEAST PREFERRED: Manual escaping
public static String escapeXPathString(String input) {
    // Replace apostrophes with the concat() function approach
    if (input.contains("'")) {
        String[] parts = input.split("'", -1);
        StringBuilder sb = new StringBuilder("concat(");
        for (int i = 0; i < parts.length; i++) {
            if (i > 0) {
                sb.append(",\"'\",");
            }
            sb.append("'").append(parts[i]).append("'");
        }
        sb.append(")");
        return sb.toString();
    }
    return "'" + input + "'";
}

// Use escaped value
String escaped = escapeXPathString(userInput);
String xpathQuery = "//users/user[username=" + escaped + "]";
```

**Warning:** This approach is fragile and should only be used when parameterization is impossible.

## Additional Defenses

### Least Privilege Data Access

Structure XML documents and XPath queries to enforce [least privilege](https://owasp.org/www-community/Access_Control):

- **Separate sensitive and non-sensitive data** into different XML documents
- **Design XPath expressions** to return only the minimum necessary data
- **Avoid broad queries** like `//user` when more specific paths like `/users/user[@role='customer']` are appropriate

### Error Handling

Prevent information disclosure through error messages:

```java
try {
    NodeList result = (NodeList) xpathExpression.evaluate(xmlDocument, XPathConstants.NODESET);
    // Process result
} catch (XPathExpressionException e) {
    // DO NOT expose XPath errors to users
    logger.error("XPath evaluation error", e);
    throw new ApplicationException("An error occurred while processing your request");
}
```

**Do not reveal:**

- XPath syntax errors (reveals query structure)
- XML structure or element names
- Whether a query returned zero or multiple results (may enable blind injection)

### Secure XML Parsing

When loading XML documents, protect against [XML External Entity (XXE)](XML_External_Entity_Prevention_Cheat_Sheet.md) attacks:

```java
// Disable external entities when parsing XML
DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
factory.setXIncludeAware(false);
factory.setExpandEntityReferences(false);

DocumentBuilder builder = factory.newDocumentBuilder();
Document xmlDocument = builder.parse(new InputSource(new StringReader(xmlContent)));
```

### Code Review and Testing

**During code review:**

1. Search for dynamic XPath construction: `XPath.compile()`, `SelectNodes()`, `evaluate()` with string concatenation
2. Verify all user input used in XPath expressions is properly parameterized or validated
3. Check that XPath variable binding is used when available
4. Confirm error messages do not leak query structure

**During security testing:**

1. Test with XPath metacharacters: `' " [ ] ( ) = ! | and or`
2. Attempt authentication bypass: `' or '1'='1`
3. Try extracting data: `' or count(//*) > 0 and '1'='1`
4. Test blind injection techniques using boolean and time-based inference

## Platform-Specific Guidance

### Python (lxml)

[Python's lxml library](https://lxml.de/xpathxslt.html) supports XPath variables through keyword arguments:

```python
# Safe: Using XPath variables in lxml
from lxml import etree

user_input = get_user_input()

tree = etree.parse('users.xml')

# Use XPath with variables (lxml extension)
result = tree.xpath('//users/user[username=$username]', username=user_input)
```

### JavaScript (Node.js with xpath)

```javascript
// Safe: Using parameterized queries
const xpath = require('xpath');
const dom = require('xmldom').DOMParser;

const userInput = req.query.username;

const doc = new dom().parseFromString(xmlContent);

// Use xpath with parameter context
const nodes = xpath.select(
    "//users/user[username=$username]",
    doc,
    { username: userInput }
);
```

### PHP (DOMXPath)

```php
// Safe: Using XPath variables (requires PHP 5.3+)
$userInput = $_GET['username'];

$doc = new DOMDocument();
$doc->load('users.xml');

$xpath = new DOMXPath($doc);

// Register custom function for variables (workaround)
$xpath->registerNamespace('php', 'http://php.net/xpath');
$xpath->registerPHPFunctions();

// Better: validate and use allow-lists
$allowedUsers = ['admin', 'user', 'guest'];
if (!in_array($userInput, $allowedUsers)) {
    throw new InvalidArgumentException('Invalid username');
}

$query = "//users/user[username='" . $userInput . "']";
$result = $xpath->query($query);
```

## References

- [CWE-643: Improper Neutralization of Data within XPath Expressions](https://cwe.mitre.org/data/definitions/643.html)
- [W3C XPath 3.1 Specification](https://www.w3.org/TR/xpath-31/)
- [Java XPathVariableResolver Documentation](https://docs.oracle.com/en/java/javase/17/docs/api/java.xml/javax/xml/xpath/XPathVariableResolver.html)
- [OWASP Testing Guide: Testing for XPath Injection](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/09-Testing_for_XPath_Injection)
- [OWASP Injection Flaws](https://owasp.org/www-community/Injection_Flaws)

## Related Cheat Sheets

- [Injection Prevention Cheat Sheet](Injection_Prevention_Cheat_Sheet.md)
- [SQL Injection Prevention Cheat Sheet](SQL_Injection_Prevention_Cheat_Sheet.md)
- [LDAP Injection Prevention Cheat Sheet](LDAP_Injection_Prevention_Cheat_Sheet.md)
- [XML External Entity Prevention Cheat Sheet](XML_External_Entity_Prevention_Cheat_Sheet.md)
- [Input Validation Cheat Sheet](Input_Validation_Cheat_Sheet.md)
