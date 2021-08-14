# Injection Prevention Cheat Sheet in Java

## Introduction

This document has for objective to provide some tips to handle *Injection* into Java application code.

Sample codes used in tips are located [here](https://github.com/righettod/injection-cheat-sheets).

## What is Injection

[Injection](https://owasp.org/www-project-top-ten/OWASP_Top_Ten_2017/Top_10-2017_A1-Injection) in OWASP Top 10 is defined as following:

*Consider anyone who can send untrusted data to the system, including external users, internal users, and administrators.*

## General advices to prevent Injection

The following point can be applied, in a general way, to prevent *Injection* issue:

1. Apply **Input Validation** (using "allow list" approach) combined with **Output Sanitizing+Escaping** on user input/output.
2. If you need to interact with system, try to use API features provided by your technology stack (Java / .Net / PHP...) instead of building command.

Additional advices are provided on this [cheatsheet](Input_Validation_Cheat_Sheet.md).

## Specific Injection types

*Examples in this section will be provided in Java technology (see Maven project associated) but advices are applicable to others technologies like .Net / PHP / Ruby / Python...*

### SQL

#### Symptom

Injection of this type occur when the application uses untrusted user input to build an SQL query using a String and execute it.

#### How to prevent

Use *Query Parameterization* in order to prevent injection.

#### Example

``` java
/*No DB framework used here in order to show the real use of
  Prepared Statement from Java API*/
/*Open connection with H2 database and use it*/
Class.forName("org.h2.Driver");
String jdbcUrl = "jdbc:h2:file:" + new File(".").getAbsolutePath() + "/target/db";
try (Connection con = DriverManager.getConnection(jdbcUrl)) {

    /* Sample A: Select data using Prepared Statement*/
    String query = "select * from color where friendly_name = ?";
    List<String> colors = new ArrayList<>();
    try (PreparedStatement pStatement = con.prepareStatement(query)) {
        pStatement.setString(1, "yellow");
        try (ResultSet rSet = pStatement.executeQuery()) {
            while (rSet.next()) {
                colors.add(rSet.getString(1));
            }
        }
    }
    Assert.assertEquals(1, colors.size());
    Assert.assertTrue(colors.contains("yellow"));

    /* Sample B: Insert data using Prepared Statement*/
    query = "insert into color(friendly_name, red, green, blue) values(?, ?, ?, ?)";
    int insertedRecordCount;
    try (PreparedStatement pStatement = con.prepareStatement(query)) {
        pStatement.setString(1, "orange");
        pStatement.setInt(2, 239);
        pStatement.setInt(3, 125);
        pStatement.setInt(4, 11);
        insertedRecordCount = pStatement.executeUpdate();
    }
    Assert.assertEquals(1, insertedRecordCount);

   /* Sample C: Update data using Prepared Statement*/
    query = "update color set blue = ? where friendly_name = ?";
    int updatedRecordCount;
    try (PreparedStatement pStatement = con.prepareStatement(query)) {
        pStatement.setInt(1, 10);
        pStatement.setString(2, "orange");
        updatedRecordCount = pStatement.executeUpdate();
    }
    Assert.assertEquals(1, updatedRecordCount);

   /* Sample D: Delete data using Prepared Statement*/
    query = "delete from color where friendly_name = ?";
    int deletedRecordCount;
    try (PreparedStatement pStatement = con.prepareStatement(query)) {
        pStatement.setString(1, "orange");
        deletedRecordCount = pStatement.executeUpdate();
    }
    Assert.assertEquals(1, deletedRecordCount);

}
```

#### References

- [SQL Injection Prevention Cheat Sheet](SQL_Injection_Prevention_Cheat_Sheet.md)

### JPA

#### Symptom

Injection of this type occur when the application uses untrusted user input to build a JPA query using a String and execute it. It's quite similar to SQL injection but here the altered language is not SQL but JPA QL.

#### How to prevent

Use Java Persistence Query Language **Query Parameterization** in order to prevent injection.

#### Example

``` java
EntityManager entityManager = null;
try {
    /* Get a ref on EntityManager to access DB */
    entityManager = Persistence.createEntityManagerFactory("testJPA").createEntityManager();

    /* Define parameterized query prototype using named parameter to enhance readability */
    String queryPrototype = "select c from Color c where c.friendlyName = :colorName";

    /* Create the query, set the named parameter and execute the query */
    Query queryObject = entityManager.createQuery(queryPrototype);
    Color c = (Color) queryObject.setParameter("colorName", "yellow").getSingleResult();

    /* Ensure that the object obtained is the right one */
    Assert.assertNotNull(c);
    Assert.assertEquals(c.getFriendlyName(), "yellow");
    Assert.assertEquals(c.getRed(), 213);
    Assert.assertEquals(c.getGreen(), 242);
    Assert.assertEquals(c.getBlue(), 26);
} finally {
    if (entityManager != null && entityManager.isOpen()) {
        entityManager.close();
    }
}
```

#### References

- [SQLi and JPA](https://software-security.sans.org/developer-how-to/fix-sql-injection-in-java-persistence-api-jpa)

### Operating System

#### Symptom

Injection of this type occur when the application uses untrusted user input to build an Operating System command using a String and execute it.

#### How to prevent

Use technology stack **API** in order to prevent injection.

#### Example

``` java
/* The context taken is, for example, to perform a PING against a computer.
* The prevention is to use the feature provided by the Java API instead of building
* a system command as String and execute it */
InetAddress host = InetAddress.getByName("localhost");
Assert.assertTrue(host.isReachable(5000));
```

#### References

- [Command Injection](https://owasp.org/www-community/attacks/Command_Injection)

### XML: XPath Injection

#### Symptom

Injection of this type occur when the application uses untrusted user input to build a XPath query using a String and execute it.

#### How to prevent

Use **XPath Variable Resolver** in order to prevent injection.

#### Example

**Variable Resolver** implementation.

``` java
/**
 * Resolver in order to define parameter for XPATH expression.
 *
 */
public class SimpleVariableResolver implements XPathVariableResolver {

    private final Map<QName, Object> vars = new HashMap<QName, Object>();

    /**
     * External methods to add parameter
     *
     * @param name Parameter name
     * @param value Parameter value
     */
    public void addVariable(QName name, Object value) {
        vars.put(name, value);
    }

    /**
     * {@inheritDoc}
     *
     * @see javax.xml.xpath.XPathVariableResolver#resolveVariable(javax.xml.namespace.QName)
     */
    public Object resolveVariable(QName variableName) {
        return vars.get(variableName);
    }
}
```

Code using it to perform XPath query.

``` java
/*Create a XML document builder factory*/
DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();

/*Disable External Entity resolution for different cases*/
//Do not performed here in order to focus on variable resolver code
//but do it for production code !

/*Load XML file*/
DocumentBuilder builder = dbf.newDocumentBuilder();
Document doc = builder.parse(new File("src/test/resources/SampleXPath.xml"));

/* Create and configure parameter resolver */
String bid = "bk102";
SimpleVariableResolver variableResolver = new SimpleVariableResolver();
variableResolver.addVariable(new QName("bookId"), bid);

/*Create and configure XPATH expression*/
XPath xpath = XPathFactory.newInstance().newXPath();
xpath.setXPathVariableResolver(variableResolver);
XPathExpression xPathExpression = xpath.compile("//book[@id=$bookId]");

/* Apply expression on XML document */
Object nodes = xPathExpression.evaluate(doc, XPathConstants.NODESET);
NodeList nodesList = (NodeList) nodes;
Assert.assertNotNull(nodesList);
Assert.assertEquals(1, nodesList.getLength());
Element book = (Element)nodesList.item(0);
Assert.assertTrue(book.getTextContent().contains("Ralls, Kim"));
```

#### References

- [XPATH Injection](https://owasp.org/www-community/attacks/XPATH_Injection)

### HTML/JavaScript/CSS

#### Symptom

Injection of this type occur when the application uses untrusted user input to build an HTTP response and sent it to browser.

#### How to prevent

Either apply strict input validation ("allow list" approach) or use output sanitizing+escaping if input validation is not possible (combine both every time is possible).

#### Example

``` java
/*
INPUT WAY: Receive data from user
Here it's recommended to use strict input validation using "allow list" approach.
In fact, you ensure that only allowed characters are part of the input received.
*/

String userInput = "You user login is owasp-user01";

/* First we check that the value contains only expected character*/
Assert.assertTrue(Pattern.matches("[a-zA-Z0-9\\s\\-]{1,50}", userInput));

/* If the first check pass then ensure that potential dangerous character
that we have allowed for business requirement are not used in a dangerous way.
For example here we have allowed the character '-', and, this can
be used in SQL injection so, we
ensure that this character is not used is a continuous form.
Use the API COMMONS LANG v3 to help in String analysis...
*/
Assert.assertEquals(0, StringUtils.countMatches(userInput.replace(" ", ""), "--"));

/*
OUTPUT WAY: Send data to user
Here we escape + sanitize any data sent to user
Use the OWASP Java HTML Sanitizer API to handle sanitizing
Use the OWASP Java Encoder API to handle HTML tag encoding (escaping)
*/

String outputToUser = "You <p>user login</p> is <strong>owasp-user01</strong>";
outputToUser += "<script>alert(22);</script><img src='#' onload='javascript:alert(23);'>";

/* Create a sanitizing policy that only allow tag '<p>' and '<strong>'*/
PolicyFactory policy = new HtmlPolicyBuilder().allowElements("p", "strong").toFactory();

/* Sanitize the output that will be sent to user*/
String safeOutput = policy.sanitize(outputToUser);

/* Encode HTML Tag*/
safeOutput = Encode.forHtml(safeOutput);
String finalSafeOutputExpected = "You <p>user login</p> is <strong>owasp-user01</strong>";
Assert.assertEquals(finalSafeOutputExpected, safeOutput);
```

#### References

- [XSS](https://owasp.org/www-community/attacks/xss/)
- [OWASP Java HTML Sanitizer](https://github.com/owasp/java-html-sanitizer)
- [OWASP Java Encoder](https://github.com/owasp/owasp-java-encoder)
- [Java RegEx](https://docs.oracle.com/javase/8/docs/api/java/util/regex/Pattern.html)

### LDAP

A dedicated [cheatsheet](LDAP_Injection_Prevention_Cheat_Sheet.md) has been created.

### NoSQL

#### Symptom

Injection of this type occur when the application uses untrusted user input to build a NoSQL API call expression.

#### How to prevent

As there many NoSQL database system and each one use an API for call, it's important to ensure that user input received and used to build the API call expression does not contain any character that have a special meaning in the target API syntax. This in order to avoid that it will be used to escape the initial call expression in order to create another one based on crafted user input. It's also important to not use string concatenation to build API call expression but use the API to create the expression.

#### Example - MongoDB

``` java
 /* Here use MongoDB as target NoSQL DB */
String userInput = "Brooklyn";

/* First ensure that the input do no contains any special characters
for the current NoSQL DB call API,
here they are: ' " \ ; { } $
*/
//Avoid regexp this time in order to made validation code
//more easy to read and understand...
ArrayList<String> specialCharsList = new ArrayList<String>() { {
    add("'");
    add("\"");
    add("\\");
    add(";");
    add("{");
    add("}");
    add("$");
} };
specialCharsList.forEach(specChar -> Assert.assertFalse(userInput.contains(specChar)));
//Add also a check on input max size
Assert.assertTrue(userInput.length() <= 50);

/* Then perform query on database using API to build expression */
//Connect to the local MongoDB instance
try(MongoClient mongoClient = new MongoClient()){
    MongoDatabase db = mongoClient.getDatabase("test");
    //Use API query builder to create call expression
    //Create expression
    Bson expression = eq("borough", userInput);
    //Perform call
    FindIterable<org.bson.Document> restaurants = db.getCollection("restaurants").find(expression);
    //Verify result consistency
    restaurants.forEach(new Block<org.bson.Document>() {
        @Override
        public void apply(final org.bson.Document doc) {
            String restBorough = (String)doc.get("borough");
            Assert.assertTrue("Brooklyn".equals(restBorough));
        }
    });
}
```

#### References

- [Testing for NoSQL injection](https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05.6-Testing_for_NoSQL_Injection.html)
- [SQL and NoSQL Injection](https://ckarande.gitbooks.io/owasp-nodegoat-tutorial/content/tutorial/a1_-_sql_and_nosql_injection.html)
- [No SQL, No Injection?](https://arxiv.org/ftp/arxiv/papers/1506/1506.04082.pdf)

### Log Injection

#### Symptom

[Log Injection](https://owasp.org/www-community/attacks/Log_Injection) occurs when an application includes untrusted data in an application log message (e.g., an attacker can cause an additional log entry that looks like it came from a completely different user, if they can inject CRLF characters in the untrusted data). More information about this attack is available on the OWASP [Log Injection](https://owasp.org/www-community/attacks/Log_Injection) page.

#### How to prevent

To prevent an attacker from writing malicious content into the application log, apply defenses such as:

- Filter the user input used to prevent injection of **C**arriage **R**eturn (CR) or **L**ine **F**eed (LF) characters.
- Limit the size of the user input value used to create the log message.
- Make sure [all XSS defenses](Cross_Site_Scripting_Prevention_Cheat_Sheet.md) are applied when viewing log files in a web browser.

#### Example using Log4j2

Configuration of a logging policy to roll on 10 files of 5MB each, and encode/limit the log message using the [Pattern *encode{}{CRLF}*](https://logging.apache.org/log4j/2.x/manual/layouts.html#PatternLayout\%7CLog4j2), introduced in [Log4j2 v2.10.0](https://mvnrepository.com/artifact/org.apache.logging.log4j/log4j-api), and the *-500m* message size limit.:

``` xml
<?xml version="1.0" encoding="UTF-8"?>
<Configuration status="error" name="SecureLoggingPolicy">
    <Appenders>
        <RollingFile name="RollingFile" fileName="App.log" filePattern="App-%i.log" ignoreExceptions="false">
            <PatternLayout>
                <!-- Encode any CRLF chars in the message and limit its
                     maximum size to 500 characters -->
                <Pattern>%d{ISO8601} %-5p - %encode{ %.-500m }{CRLF}%n</Pattern>
            </PatternLayout>
            <Policies>
                <SizeBasedTriggeringPolicy size="5MB"/>
            </Policies>
            <DefaultRolloverStrategy max="10"/>
        </RollingFile>
    </Appenders>
    <Loggers>
        <Root level="debug">
            <AppenderRef ref="RollingFile"/>
        </Root>
    </Loggers>
</Configuration>
```

Usage of the logger at code level:

``` java
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
...
// No special action needed because security actions are
// performed at the logging policy level
Logger logger = LogManager.getLogger(MyClass.class);
logger.info(logMessage);
...
```

#### Example using Logback with the OWASP Security Logging library

Configuration of a logging policy to roll on 10 files of 5MB each, and encode/limit the log message using the [CRLFConverter](https://github.com/javabeanz/owasp-security-logging/wiki/Log-Forging), provided by the [OWASP Security Logging Project](https://owasp.org/www-project-security-logging/), and the *-500msg* message size limit:

``` xml
<?xml version="1.0" encoding="UTF-8"?>
<configuration>
    <!-- Define the CRLFConverter -->
    <conversionRule conversionWord="crlf" converterClass="org.owasp.security.logging.mask.CRLFConverter" />
    <appender name="RollingFile" class="ch.qos.logback.core.rolling.RollingFileAppender">
        <file>App.log</file>
        <rollingPolicy class="ch.qos.logback.core.rolling.FixedWindowRollingPolicy">
            <fileNamePattern>App-%i.log</fileNamePattern>
            <minIndex>1</minIndex>
            <maxIndex>10</maxIndex>
        </rollingPolicy>
        <triggeringPolicy class="ch.qos.logback.core.rolling.SizeBasedTriggeringPolicy">
            <maxFileSize>5MB</maxFileSize>
        </triggeringPolicy>
        <encoder>
            <!-- Encode any CRLF chars in the message and limit
                 its maximum size to 500 characters -->
            <pattern>%relative [%thread] %-5level %logger{35} - %crlf(%.-500msg) %n</pattern>
        </encoder>
    </appender>
    <root level="debug">
        <appender-ref ref="RollingFile" />
    </root>
</configuration>
```

You also have to add the [OWASP Security Logging](https://github.com/javabeanz/owasp-security-logging/wiki/Usage-with-Logback) dependency to your project.

Usage of the logger at code level:

``` java
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
...
// No special action needed because security actions
// are performed at the logging policy level
Logger logger = LoggerFactory.getLogger(MyClass.class);
logger.info(logMessage);
...
```

#### References

- [PatternLayout](https://logging.apache.org/log4j/2.x/manual/layouts.html#PatternLayout) (See the `encode{}{CRLF}` function)

```text
Note that the default Log4j2 encode{} encoder is HTML, which does NOT prevent log injection.

It prevents XSS attacks against viewing logs using a browser.

OWASP recommends defending against XSS attacks in such situations in the log viewer application itself,
not by preencoding all the log messages with HTML encoding as such log entries may be used/viewed in many
other log viewing/analysis tools that don't expect the log data to be pre-HTML encoded.
```

- [LOG4J Configuration](https://logging.apache.org/log4j/2.x/manual/configuration.html)
- [LOG4J Appender](https://logging.apache.org/log4j/2.x/manual/appenders.html)
- [Log Forging](https://github.com/javabeanz/owasp-security-logging/wiki/Log-Forging) - See the Logback section about the `CRLFConverter` this library provides.
- [Usage of OWASP Security Logging with Logback](https://github.com/javabeanz/owasp-security-logging/wiki/Usage-with-Logback)
