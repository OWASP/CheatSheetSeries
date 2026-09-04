# XML External Entity Prevention Cheat Sheet

## Introduction

An *XML eXternal Entity injection* (XXE), which is now part of the [OWASP Top 10](https://owasp.org/www-project-top-ten/OWASP_Top_Ten_2017/Top_10-2017_A4-XML_External_Entities_%28XXE%29) via the point **A4**, is attack against applications that parse XML input. This issue is referenced in the ID [611](https://cwe.mitre.org/data/definitions/611.html) in the [Common Weakness Enumeration](https://cwe.mitre.org/index.html) referential. An XXE attack occurs when untrusted XML input with a **reference to an external entity is processed by a weakly configured XML parser**, and this attack could be used to stage multiple incidents, including:

- A denial of service attack on the system
- A [Server Side Request Forgery](https://owasp.org/www-community/attacks/Server_Side_Request_Forgery) (SSRF) attack
- The ability to scan ports from the machine where the parser is located
- Other system impacts.

This cheat sheet will help you prevent this vulnerability.

For more information on XXE, please visit [XML External Entity (XXE)](https://en.wikipedia.org/wiki/XML_external_entity_attack).

## General Guidance

**The safest way to prevent XXE is always to disable DTDs (External Entities) completely.** Depending on the parser, the method should be similar to the following:

``` java
factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
```

Disabling [DTD](https://www.w3schools.com/xml/xml_dtd.asp)s also makes the parser secure against denial of services (DOS) attacks such as [Billion Laughs](https://en.wikipedia.org/wiki/Billion_laughs_attack). **If it is not possible to disable DTDs completely, then external entities and external document type declarations must be disabled in the way that's specific to each parser.**

### XML Parser Security Features Matrix

| Security Feature                                | Default (Parser-Dependent)  | Purpose                                               | **What Happens If Missing?**                              |
| ----------------------------------------------- | --------------------------- | ----------------------------------------------------- | --------------------------------------------------------- |
| **External Entities Disabled**                  | Usually **disabled** (safe) | Blocks external resource loading                      | Full XXE possible → SSRF, file disclosure, internal scans |
| **Disallow DOCTYPE Declaration**                | Varies                      | Prevents ENTITY definitions                           | Classic XXE payloads become fully functional              |
| **Disable External DTD Loading**                | Usually **disabled**        | Stops loading remote DTDs                             | Enables Blind XXE, SSRF behind firewalls                  |
| **Secure Processing Mode**                      | Varies                      | Restricts recursion, network access, entity expansion | Billion Laughs DoS and resource depletion become possible |
| **Disable Parameter Entities**                  | Varies                      | Prevents `%entity;` injections                        | Advanced XXE payloads bypass simple protections           |
| **XInclude Disabled**                           | Usually **disabled**        | Prevents including external files                     | File read via `file://` and SSRF becomes possible         |
| **Limit Entity Expansion Count**                | Usually **enabled**         | Prevents recursive entity abuse                       | Memory exhaustion → parser or server DoS                  |
| **Schema Validation Without External Fetching** | Usually safe                | Ensures validation does not fetch external URLs       | Silent external HTTP calls triggered during validation    |

### Quick Impact Matrix (What Happens If Missing?)

| Missing Control                         | Resulting Vulnerability                      |
| --------------------------------------- | -------------------------------------------- |
| DOCTYPE not disabled                    | Standard XXE fully exploitable               |
| External entities enabled               | SSRF, file exfiltration, port scanning       |
| External DTD loading allowed            | Blind XXE → hidden SSRF attacks              |
| No expansion limits                     | Billion Laughs DoS                           |
| XInclude enabled                        | Local file disclosure + SSRF                 |
| Secure processing disabled              | Critical protections bypassed                |
| Schema validation fetches external URLs | Application makes unwanted outbound requests |

### Minimal XML Hardening Rules

- Disable DOCTYPE
- Disable external entities
- Disable external DTD loading
- Enable secure processing mode
- Disable XInclude
- Limit entity expansion
- Do not use legacy XML parsers
- Never parse untrusted XML with default settings

**Detailed XXE Prevention guidance is provided below for multiple languages (C++, Cold Fusion, Java, .NET, iOS, PHP, Python, Semgrep Rules) and their commonly used XML parsers.**

## C/C++

### libxml2

The Enum [xmlParserOption](http://xmlsoft.org/html/libxml-parser.html#xmlParserOption) should not have the following options defined:

- `XML_PARSE_NOENT`: Expands entities and substitutes them with replacement text
- `XML_PARSE_DTDLOAD`: Load the external DTD

Note:

Per: According to [this post](https://mail.gnome.org/archives/xml/2012-October/msg00045.html), starting with libxml2 version 2.9, XXE has been disabled by default as committed by the following [patch](https://gitlab.gnome.org/GNOME/libxml2/commit/4629ee02ac649c27f9c0cf98ba017c6b5526070f).

Search whether the following APIs are being used and make sure there is no `XML_PARSE_NOENT` and `XML_PARSE_DTDLOAD` defined in the parameters:

- `xmlCtxtReadDoc`
- `xmlCtxtReadFd`
- `xmlCtxtReadFile`
- `xmlCtxtReadIO`
- `xmlCtxtReadMemory`
- `xmlCtxtUseOptions`
- `xmlParseInNodeContext`
- `xmlReadDoc`
- `xmlReadFd`
- `xmlReadFile`
- `xmlReadIO`
- `xmlReadMemory`

### libxerces-c

Use of `XercesDOMParser` do this to prevent XXE:

``` cpp
XercesDOMParser *parser = new XercesDOMParser;
parser->setCreateEntityReferenceNodes(true);
parser->setDisableDefaultEntityResolution(true);
```

Use of SAXParser, do this to prevent XXE:

``` cpp
SAXParser* parser = new SAXParser;
parser->setDisableDefaultEntityResolution(true);
```

Use of SAX2XMLReader, do this to prevent XXE:

``` cpp
SAX2XMLReader* reader = XMLReaderFactory::createXMLReader();
parser->setFeature(XMLUni::fgXercesDisableDefaultEntityResolution, true);
```

## ColdFusion

Per [this blog post](https://hoyahaxa.blogspot.com/2022/11/on-coldfusion-xxe-and-other-xml-attacks.html), both Adobe ColdFusion and Lucee have built-in mechanisms to disable support for external XML entities.

### Adobe ColdFusion

As of ColdFusion 2018 Update 14 and ColdFusion 2021 Update 4, all native ColdFusion functions that process XML have a XML parser argument that disables support for external XML entities. Since there is no global setting that disables external entities, developers must ensure that every XML function call uses the correct security options.

From the [documentation for the XmlParse() function](https://helpx.adobe.com/coldfusion/cfml-reference/coldfusion-functions/functions-t-z/xmlparse.html), you can disable XXE with the code below:

```
<cfset parseroptions = structnew()>
<cfset parseroptions.ALLOWEXTERNALENTITIES = false>
<cfscript>
a = XmlParse("xml.xml", false, parseroptions);
writeDump(a);
</cfscript>
```

You can use the "parseroptions" structure shown above as an argument to secure other functions that process XML as well, such as:

```
XxmlSearch(xmldoc, xpath,parseroptions);

XmlTransform(xmldoc,xslt,parseroptions);

isXML(xmldoc,parseroptions);
```

### Lucee

As of Lucee 5.3.4.51 and later, you can disable support for XML external entities by adding the following to your Application.cfc:

```
this.xmlFeatures = {
     externalGeneralEntities: false,
     secure: true,
     disallowDoctypeDecl: true
};
```

Support for external XML entities is disabled by default as of Lucee 5.4.2.10 and Lucee 6.0.0.514.

## Java

Java is exposed to XXE for two structural reasons, and both have to be dealt with before any individual recipe matters:

- **The parser is chosen at deployment time.** JAXP factories are pluggable, so the implementation a `newInstance()` call returns depends on the classpath rather than on your code.
- **Almost no security setting is mandatory.** The features that disable external entity resolution are optional, so a parser is free not to recognize them and throw an exception, which users often swallow.

### Pick the implementation

`newInstance()` does not return a known parser. The [JAXP lookup mechanism](https://docs.oracle.com/en/java/javase/25/docs/api/java.xml/module-summary.html#LookupMechanism) resolves the implementation from system properties and the classpath. That choice is made outside your code, and every recipe below is implementation-specific: if you do not know which parser you have, you do not know which settings it honors.

[`newDefaultInstance()`](https://docs.oracle.com/en/java/javase/25/docs/api/java.xml/javax/xml/parsers/DocumentBuilderFactory.html#newDefaultInstance()) (Java 9 and later; `newDefaultFactory()` for StAX) bypasses the lookup and returns the built-in implementation. Prefer it when your XML needs are modest: you then know which settings apply. The cost is that an operator can no longer substitute a faster or more capable parser.

### Fail closed

Since [version 1.3 in Java 5](https://docs.oracle.com/javase/1.5.0/docs/api/javax/xml/parsers/DocumentBuilderFactory.html#setFeature(java.lang.String,%20boolean)), JAXP mandates only one security-related setting. Both [`DocumentBuilderFactory.setFeature`](https://docs.oracle.com/en/java/javase/25/docs/api/java.xml/javax/xml/parsers/DocumentBuilderFactory.html#setFeature(java.lang.String,boolean)) and [`SAXParserFactory.setFeature`](https://docs.oracle.com/en/java/javase/25/docs/api/java.xml/javax/xml/parsers/SAXParserFactory.html#setFeature(java.lang.String,boolean)) state that all implementations are required to support `FEATURE_SECURE_PROCESSING`; `XMLInputFactory` carries no such requirement. Twenty years on it remains the only one, and it merely enables the implementation's processing limits — it does not block external access.

Everything that does block external access is optional:

- `ACCESS_EXTERNAL_DTD`, `ACCESS_EXTERNAL_SCHEMA` and `ACCESS_EXTERNAL_STYLESHEET` arrived with JAXP 1.5, which still only the JDK's built-in implementation provides — [Apache Xerces](https://xerces.apache.org/xerces2-j/) does not.
- `disallow-doctype-decl` and `load-external-dtd` are Apache extensions, in Xerces' own `http://apache.org/xml/features/` namespace.
- `external-general-entities` and `external-parameter-entities` are optional SAX2 features.

A parser that does not recognize one says so: `SAXNotRecognizedException` from SAX, `ParserConfigurationException` from JAXP. **That exception means the hardening was not applied.** Catching it and continuing — as many published examples do — leaves you parsing untrusted XML with an unconfigured parser, which is the exact situation the recipe was meant to prevent.

``` java
DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
try {
    // Primary defense: reject any document carrying a DOCTYPE.
    dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
    dbf.setXIncludeAware(false);
} catch (ParserConfigurationException e) {
    // The parser did not recognize the feature, so nothing was hardened.
    // Refuse to parse rather than continuing with an unconfigured factory.
    throw new IllegalStateException("Unable to secure the XML parser", e);
}
DocumentBuilder builder = dbf.newDocumentBuilder();
```

Where no feature is recognized, an ignore-all resolver is the fallback, because the resolver interfaces *are* part of the API every implementation must provide. SEI CERT recommends [supplying a no-op implementation](https://wiki.sei.cmu.edu/confluence/display/java/IDS17-J.+Prevent+XML+External+Entity+Attacks):

``` java
// Empty content, not null: null tells the parser to resolve the reference itself.
EntityResolver ignoreAll = (publicId, systemId) -> new InputSource(new StringReader(""));
documentBuilder.setEntityResolver(ignoreAll);
```

### DOM: DocumentBuilderFactory

DOM has four maintained implementations:

- [Apache Xerces](https://xerces.apache.org/xerces2-j/),
- The built-in JDK parser derived from Xerces,
- The built-in Android parser, which [builds a DOM using kXML](https://android.googlesource.com/platform/libcore/+/refs/heads/main/luni/src/main/java/org/apache/harmony/xml/parsers/DocumentBuilderImpl.java),
- The [Oracle XML Developer's Kit](https://docs.oracle.com/en/database/oracle/oracle-database/21/adxdk/security-considerations-oracle-xml-developers-kit.html), whose JAXP binding recognizes only `FEATURE_SECURE_PROCESSING`, and which is also usable directly through its own API (covered below).

Disabling DTDs outright is the primary defense and stops nearly every XXE variant. The settings available to do it differ by implementation:

| Setting                                                                                                                                          | Safe value         | Recognized by                        | Effect                                                                       |
|--------------------------------------------------------------------------------------------------------------------------------------------------|--------------------|--------------------------------------|------------------------------------------------------------------------------|
| [`jdk.xml.dtd.support`](https://docs.oracle.com/en/java/javase/25/docs/api/java.xml/module-summary.html#jdk.xml.dtd.support)                     | `deny` or `ignore` | Built-in JDK parsers (Java 22+)      | Rejects or ignores DTDs across DOM, SAX, StAX, validation and transformation |
| [`disallow-doctype-decl`](https://xerces.apache.org/xerces2-j/features.html#disallow-doctype-decl)                                               | `true`             | Xerces and derivatives               | Rejects any document with a DOCTYPE                                          |
| [`ACCESS_EXTERNAL_DTD`](https://docs.oracle.com/en/java/javase/25/docs/api/java.xml/javax/xml/XMLConstants.html#ACCESS_EXTERNAL_DTD)             | `""`               | Built-in JDK parsers (Java 7u40+)    | Rejects external DTDs and external entity references                         |
| [`ACCESS_EXTERNAL_SCHEMA`](https://docs.oracle.com/en/java/javase/25/docs/api/java.xml/javax/xml/XMLConstants.html#ACCESS_EXTERNAL_SCHEMA)       | `""`               | Built-in JDK parsers (Java 7u40+)    | Rejects schemas named by `schemaLocation`, `xs:import` and `xs:include`      |
| [`external-general-entities`](https://xerces.apache.org/xerces2-j/features.html#external-general-entities)                                       | `false`            | Optional SAX2 feature                | Ignores external general entities                                            |
| [`external-parameter-entities`](https://xerces.apache.org/xerces2-j/features.html#external-parameter-entities)                                   | `false`            | Optional SAX2 feature                | Ignores external parameter entities                                          |
| [`load-external-dtd`](https://xerces.apache.org/xerces2-j/features.html#nonvalidating/load-external-dtd)                                         | `false`            | Xerces and derivatives               | Ignores the external subset (non-validating only)                            |
| [`FEATURE_SECURE_PROCESSING`](https://docs.oracle.com/en/java/javase/25/docs/api/java.xml/javax/xml/XMLConstants.html#FEATURE_SECURE_PROCESSING) | `true`             | Required of DOM and SAX; not Android | Enables the implementation's own processing limits                           |

To secure `DocumentBuilderFactory` through features:

- Use `disallow-doctype-decl` on the JVM, where a Xerces-derived parser is usually present.

- If your application genuinely needs internal DTDs and entities, disable the external-entity features instead. All **three** must be set together: `external-general-entities`, `external-parameter-entities` and `load-external-dtd`. A single feature left enabled leaves an exploitable path.

- Setting `FEATURE_SECURE_PROCESSING` **explicitly through the API** sets the **default** value of `ACCESS_EXTERNAL_DTD` and `ACCESS_EXTERNAL_SCHEMA` to the empty string on built-in JDK parsers. Operators can still override that default, which sits below both a system property and the configuration file in the [property precedence](https://docs.oracle.com/en/java/javase/25/docs/api/java.xml/module-summary.html#Conf_PP). Oracle's XDK treats the same feature as a real access control and [lists it](https://docs.oracle.com/en/database/oracle/oracle-database/21/adxdk/security-considerations-oracle-xml-developers-kit.html) among the settings that secure its JAXP binding, so what the feature buys you depends on the implementation.

Settings that make the parser insecure (keep them to their `false` default):

- If you call [`setValidating(true)`](https://docs.oracle.com/en/java/javase/25/docs/api/java.xml/javax/xml/parsers/DocumentBuilderFactory.html#setValidating(boolean)), `load-external-dtd` no longer applies, because it is ["always on when validation is on"](https://xerces.apache.org/xerces2-j/features.html#nonvalidating/load-external-dtd).

- If you call [`setXIncludeAware(true)`](https://docs.oracle.com/en/java/javase/25/docs/api/java.xml/javax/xml/parsers/DocumentBuilderFactory.html#setXIncludeAware(boolean)), you open a separate external fetch channel, one that only a resolver can close.

**`setExpandEntityReferences` is a false friend.** It governs how entities are represented in the tree, not whether they are fetched: the Javadoc defines it as whether the parser ["will expand entity reference nodes"](https://docs.oracle.com/en/java/javase/25/docs/api/java.xml/javax/xml/parsers/DocumentBuilderFactory.html#setExpandEntityReferences(boolean)). Oracle nonetheless lists it among the XDK's security settings — the same JAXP method carries different weight on different implementations, which is the reason to know which parser you have.

### SAX: SAXParserFactory and XMLReader

The same lineages apply, except that Android's SAX reader is [based on `expat`](https://android.googlesource.com/platform/libcore/+/refs/heads/main/luni/src/main/java/org/apache/harmony/xml/ExpatReader.java) rather than kXML. The same features apply too, with two differences:

- `SAXParserFactory` exposes only a feature API, so anything expressed as a property has to be set on the `XMLReader` obtained from `SAXParser.getXMLReader()`.
- Get the reader through `SAXParserFactory` rather than the `XMLReaderFactory.createXMLReader()` shown in older guidance, which has been deprecated since Java 9.

More importantly, **`SAXParser.parse(source, DefaultHandler)` installs that handler as the reader's `EntityResolver`**, silently replacing any resolver you configured with one that returns `null`. That happens in [`SAXParser` itself](https://github.com/openjdk/jdk/blob/6c48f4ed707bf0b15f9b6098de30db8aae6fa40f/src/java.xml/share/classes/javax/xml/parsers/SAXParser.java#L389-L392) rather than in an implementation, so no parser escapes it.

### StAX: XMLInputFactory

StAX has two implementations, the built-in JDK reader and [Woodstox](https://github.com/FasterXML/woodstox), and is absent from both Android and the Oracle XDK.

The StAX specification **does** support security-related properties, but they default to `true` or are unspecified:

| Setting                                                                                                                                                                | Safe value | Effect                                                                                                                                                                                                                               |
|------------------------------------------------------------------------------------------------------------------------------------------------------------------------|------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| [`jdk.xml.dtd.support`](https://docs.oracle.com/en/java/javase/25/docs/api/java.xml/module-summary.html#jdk.xml.dtd.support)                                           | `deny`     | Rejects any document with a DOCTYPE (built-in JDK parsers, [Java 22+](https://bugs.openjdk.org/browse/JDK-8306632))                                                                                                                  |
| [`SUPPORT_DTD`](https://docs.oracle.com/en/java/javase/25/docs/api/java.xml/javax/xml/stream/XMLInputFactory.html#SUPPORT_DTD)                                         | `false`    | [Skips the DTD](https://github.com/openjdk/jdk/blob/jdk-25-ga/src/java.xml/share/classes/com/sun/org/apache/xerces/internal/impl/XMLDTDScannerImpl.java#L379) rather than rejecting it: no internal subset, no external subset fetch |
| [`IS_SUPPORTING_EXTERNAL_ENTITIES`](https://docs.oracle.com/en/java/javase/25/docs/api/java.xml/javax/xml/stream/XMLInputFactory.html#IS_SUPPORTING_EXTERNAL_ENTITIES) | `false`    | Does not resolve external parsed entities                                                                                                                                                                                            |

Set both StAX properties. `setProperty` throws an unchecked `IllegalArgumentException` on a name the implementation does not know, so this already fails closed:

``` java
XMLInputFactory xif = XMLInputFactory.newInstance();
xif.setProperty(XMLInputFactory.SUPPORT_DTD, false);
xif.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, false);
```

StAX has no equivalent of `FEATURE_SECURE_PROCESSING`, so entity-expansion bounds are whatever the implementation applies on its own.

If you install an [`XMLResolver`](https://docs.oracle.com/en/java/javase/25/docs/api/java.xml/javax/xml/stream/XMLResolver.html) instead, note that it must return an `InputStream`, `XMLStreamReader` or `XMLEventReader`. Any other value is undefined and may be treated as `null`, which is what the built-in JDK parser does, causing the external resource to be fetched.

### Oracle DOM Parser

The [Oracle XML Developer's Kit](https://docs.oracle.com/en/database/oracle/oracle-database/21/adxdk/security-considerations-oracle-xml-developers-kit.html) (`oracle.xml.parser.v2`) is a separate implementation with a parser API of its own.

On its `DOMParser`, call `setSecureProcessing()`. In one call it disables entity resolution and bounds entity expansion, which is the whole XXE recipe for this parser. It takes no argument and cannot be reversed. The method sits on the shared `XMLParser` base class, so the XDK's SAX parser is secured the same way.

Setting `FEATURE_SECURE_PROCESSING` on its JAXP binding applies the equivalent hardening.

### Parsers that wrap a JAXP parser

These libraries do not parse XML themselves, and both let you supply the parser. Harden an `XMLReader` as in the SAX section and hand it over, rather than relying on the wrapper to forward settings — the same rule as for the interfaces below.

| Library                           | How to supply the reader                                                                                                                                                                        |
|-----------------------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| [dom4j](https://dom4j.github.io/) | [`SAXReader.setXMLReader(XMLReader)`](https://javadoc.io/doc/org.dom4j/dom4j/latest/org/dom4j/io/SAXReader.html#setXMLReader(org.xml.sax.XMLReader)), or the matching constructor               |
| [JDOM](https://www.jdom.org/)     | [`SAXBuilder(XMLReaderJDOMFactory)`](https://www.jdom.org/docs/apidocs/org/jdom2/input/SAXBuilder.html#SAXBuilder-org.jdom2.input.sax.XMLReaderJDOMFactory-), whose factory returns your reader |

Other libraries follow the same pattern: check whether the one you use accepts a parser, and give it a hardened one. If it exposes no such control, parse the untrusted content yourself first and hand the resulting document to the library.

### Interfaces that need a parser

`TransformerFactory`, `SchemaFactory`, `Validator`, `XPathFactory` and the JAXB `Unmarshaller` are not parsers. They *consume* one, and if you do not supply it, they build their own. Give them one you hardened; which kind depends on the interface.

#### TrAX and validation take a SAX parser

`TransformerFactory`, `SchemaFactory` and `Validator` accept a `Source`. Wrap the input in a `SAXSource` carrying an `XMLReader` you configured:

``` java
// Create a hardened reader
XMLReader reader = ...;

// Validator.validate() takes the same SAXSource
transformer.transform(new SAXSource(reader, new InputSource(inputStream)), result);
```

On the built-in JDK implementations, `ACCESS_EXTERNAL_DTD` set on the factory is copied onto the reader, so it also covers the source document. Set `ACCESS_EXTERNAL_SCHEMA` and `ACCESS_EXTERNAL_STYLESHEET` as well, to block the schema and style sheet references the factory resolves on its own behalf, such as `xs:include` and `xsl:import`.

Two gaps leave a hardened factory producing an unhardened object:

- A `SchemaFactory`'s resolver is not inherited, by contract (see [`setResourceResolver`](https://docs.oracle.com/en/java/javase/25/docs/api/java.xml/javax/xml/validation/SchemaFactory.html#setResourceResolver(org.w3c.dom.ls.LSResourceResolver))). Install it again on the `Schema`s, `Validator`s, or `ValidatorHandler`s created from it.
- `getAssociatedStylesheet` discards your reader on older implementations (see [XALANJ-2849](https://issues.apache.org/jira/browse/XALANJ-2849) and older JDK versions), scanning with a parser of its own. Pass it a `DOMSource` you parsed yourself, and treat the `Source` it returns as untrusted: its system identifier comes from document content, so re-parse that identifier rather than handing the `Source` to `newTransformer`.

#### XPath takes a DOM

The contract leaves the context type implementation-dependent: [`XPath.evaluate`](https://docs.oracle.com/en/java/javase/25/docs/api/java.xml/javax/xml/xpath/XPath.html#evaluate(java.lang.String,java.lang.Object)) notes only that it usually accepts `Node`". Parse the document yourself with a hardened `DocumentBuilder` and evaluate against the resulting `Document`. Avoid the `InputSource` overloads: they build the document with a `DocumentBuilderFactory` you never get to configure.

#### JAXB takes a StAX reader

Feed the [`Unmarshaller`](https://jakarta.ee/specifications/xml-binding/4.0/apidocs/jakarta.xml.bind/jakarta/xml/bind/Unmarshaller.html) an `XMLStreamReader` created by a hardened `XMLInputFactory`. JAXB left the JDK in Java 11 and now ships as `jakarta.xml.bind`.

``` java
// Create a hardened reader
XMLStreamReader xsr = ...;

Object result = jaxbContext.createUnmarshaller().unmarshal(xsr);
```

### java.beans.XMLDecoder

[`XMLDecoder.readObject()`](https://docs.oracle.com/en/java/javase/25/docs/api/java.desktop/java/beans/XMLDecoder.html#readObject()) has the rare privilege of joining together the dangers of XXE with the power of object binding. Don't use it for **untrusted** data.

### Secure JAXP factory sources

Secure XML factory configuration is complex and has other edge cases. This is why most projects contain utility classes to configure parsers to their needs.

[Apache Commons Secure XML](https://commons.apache.org/proper/commons-secure-xml/) is a recent (2026) standalone library, whose only purpose is to provide secure JAXP factories and backport `newDefaultInstance()` methods to Java 8. It is based on **resolvers**, and wraps the objects a factory produces so those are secured too. Its [threat model](https://github.com/apache/commons-secure-xml/blob/main/src/site/markdown/threat_model.md) documents which guarantees hold and which settings the caller is not allowed to change.

## .NET

**Up-to-date information for XXE injection in .NET is taken directly from the [web application of unit tests by Dean Fleming](https://github.com/deanf1/dotnet-security-unit-tests), which covers all currently supported .NET XML parsers, and has test cases that demonstrate when they are safe from XXE injection and when they are not, but these tests are only with injection from file and not direct DTD (used by DoS attacks).**

For DoS attacks using a direct DTD (such as the [Billion laughs attack](https://en.wikipedia.org/wiki/Billion_laughs_attack)), a [separate testing application from Josh Grossman at Bounce Security](https://github.com/BounceSecurity/BillionLaughsTester) has been created to verify that .NET >=4.5.2 is safe from these attacks.

Previously, this information was based on some older articles which may not be 100% accurate including:

- [James Jardine's excellent .NET XXE article](https://www.jardinesoftware.net/2016/05/26/xxe-and-net/).
- [Guidance from Microsoft on how to prevent XXE and XML Denial of Service in .NET](http://msdn.microsoft.com/en-us/magazine/ee335713.aspx).

### Overview of .NET Parser Safety Levels

**Below is an overview of all supported .NET XML parsers and their default safety levels. More details about each parser are included after this list.

**XDocument (LINQ to XML)

This parser is protected from external entities at .NET Framework version 4.5.2 and protected from Billion Laughs at version 4.5.2 or greater, but it is uncertain if this parser is protected from Billion Laughs before version 4.5.2.

#### XmlDocument, XmlTextReader, XPathNavigator default safety levels

These parsers are vulnerable to external entity attacks and Billion Laughs at versions below version 4.5.2 but protected at versions equal or greater than 4.5.2.

#### XmlDictionaryReader, XmlNodeReader, XmlReader default safety levels

These parsers are not vulnerable to external entity attacks or Billion Laughs before or after version 4.5.2. Also, at or greater than versions ≥4.5.2, these libraries won't even process the in-line DTD by default. Even if you change the default to allow processing a DTD, if a DoS attempt is performed an exception will still be thrown as documented above.

### ASP.NET

ASP.NET applications ≥ .NET 4.5.2 must also ensure setting the `<httpRuntime targetFramework="..." />` in their `Web.config` to ≥4.5.2 or risk being vulnerable regardless or the actual .NET version. Omitting this tag will also result in unsafe-by-default behavior.

For the purpose of understanding the above table, the `.NET Framework Version` for an ASP.NET applications is either the .NET version the application was build with or the httpRuntime's `targetFramework` (Web.config), **whichever is lower**.

This configuration tag should not be confused with a similar configuration tag: `<compilation targetFramework="..." />` or the assemblies / projects targetFramework, which are **not** sufficient for achieving secure-by-default behavior as advertised in the above table.

### LINQ to XML

**Both the `XElement` and `XDocument` objects in the `System.Xml.Linq` library are safe from XXE injection from external file and DoS attack by default.** `XElement` parses only the elements within the XML file, so DTDs are ignored altogether. `XDocument` has XmlResolver [disabled by default](https://docs.microsoft.com/en-us/dotnet/standard/linq/linq-xml-security) so it's safe from SSRF. While DTDs are [enabled by default](https://referencesource.microsoft.com/#System.Xml.Linq/System/Xml/Linq/XLinq.cs,71f4626a3d6f9bad), from Framework versions ≥4.5.2, it is **not** vulnerable to DoS as noted but it may be vulnerable in earlier Framework versions. For more information, see [Microsoft's guidance on how to prevent XXE and XML Denial of Service in .NET](http://msdn.microsoft.com/en-us/magazine/ee335713.aspx)

### XmlDictionaryReader

**`System.Xml.XmlDictionaryReader` is safe by default, as when it attempts to parse the DTD, the compiler throws an exception saying that "CData elements not valid at top level of an XML document". It becomes unsafe if constructed with a different unsafe XML parser.**

### XmlDocument

**Prior to .NET Framework version 4.5.2, `System.Xml.XmlDocument` is unsafe by default. The `XmlDocument` object has an `XmlResolver` object within it that needs to be set to null in versions prior to 4.5.2. In versions 4.5.2 and up, this `XmlResolver` is set to null by default.**

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

**For .NET Framework version ≥4.5.2, this is safe by default**.

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

**In .NET Framework version 4.0, DTD parsing behavior has been changed. The `ProhibitDtd` property has been deprecated in favor of the new `DtdProcessing` property.**

**However, they didn't change the default settings so `XmlTextReader` is still vulnerable to XXE by default.**

**Setting `DtdProcessing` to `Prohibit` causes the runtime to throw an exception if a `<!DOCTYPE>` element is present in the XML.**

To set this value yourself, it looks like this:

``` csharp
XmlTextReader reader = new XmlTextReader(stream);
// NEEDED because the default is Parse!!
reader.DtdProcessing = DtdProcessing.Prohibit;  
```

Alternatively, you can set the `DtdProcessing` property to `Ignore`, which will not throw an exception on encountering a `<!DOCTYPE>` element but will simply skip over it and not process it. Finally, you can set `DtdProcessing` to `Parse` if you do want to allow and process inline DTDs.

#### .NET 4.5.2 and later

In .NET Framework versions 4.5.2 and up, `XmlTextReader`'s internal `XmlResolver` is set to null by default, making the `XmlTextReader` ignore DTDs by default. The `XmlTextReader` can become unsafe if you create your own nonnull `XmlResolver` with default or unsafe settings.

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

For .NET Framework version ≥4.5.2, XPathNavigator is **safe by default**.

### XslCompiledTransform

`System.Xml.Xsl.XslCompiledTransform` (an XML transformer) is safe by default as long as the parser it's given is safe.

It is safe by default because the default parser of the `Transform()` methods is an `XmlReader`, which is safe by default (per above).

[The source code for this method is here.](http://www.dotnetframework.org/default.aspx/4@0/4@0/DEVDIV_TFS/Dev10/Releases/RTMRel/ndp/fx/src/Xml/System/Xml/Xslt/XslCompiledTransform@cs/1305376/XslCompiledTransform@cs)

Some of the `Transform()` methods accept an `XmlReader` or `IXPathNavigable` (e.g., `XmlDocument`) as an input, and if you pass in an unsafe XML Parser then the `Transform` will also be unsafe.

## iOS

### libxml2

**iOS includes the C/C++ libxml2 library described above, so that guidance applies if you are using libxml2 directly.**

**However, the version of libxml2 provided up through iOS6 is prior to version 2.9 of libxml2 (which protects against XXE by default).**

### NSXMLDocument

**iOS also provides an `NSXMLDocument` type, which is built on top of libxml2.**

**However, `NSXMLDocument` provides some additional protections against XXE that aren't available in libxml2 directly.**

Per the 'NSXMLDocument External Entity Restriction API' section of this [page](https://developer.apple.com/library/archive/releasenotes/Foundation/RN-Foundation-iOS/Foundation_iOS5.html):

- iOS4 and earlier: All external entities are loaded by default.
- iOS5 and later: Only entities that don't require network access are loaded. (which is safer)

**However, to completely disable XXE in an `NSXMLDocument` in any version of iOS you simply specify `NSXMLNodeLoadExternalEntitiesNever` when creating the `NSXMLDocument`.**

## PHP

**When using the default XML parser (based on libxml2), PHP 8.0 and newer [prevent XXE by default](https://www.php.net/manual/en/function.libxml-disable-entity-loader.php).**

**For PHP versions prior to 8.0, per [the PHP documentation](https://www.php.net/manual/en/function.libxml-set-external-entity-loader.php), the following should be set when using the default PHP XML parser in order to prevent XXE:**

``` php
libxml_set_external_entity_loader(null);
```

A description of how to abuse this in PHP is presented in a good [SensePost article](https://www.sensepost.com/blog/2014/revisting-xxe-and-abusing-protocols/) describing a cool PHP based XXE vulnerability that was fixed in Facebook.

## Python

The Python 3 official documentation contains a section on [xml vulnerabilities](https://docs.python.org/3/library/xml.html#xml-vulnerabilities). As of the 1st January 2020 Python 2 is no longer supported, however the Python website still contains [some legacy documentation](https://docs.Python.org/2/library/xml.html#xml-vulnerabilities).

The table below shows you which various XML parsing modules in Python 3 are vulnerable to certain XXE attacks.

| Attack Type               | sax        | etree      | minidom    | pulldom    | xmlrpc     |
|---------------------------|------------|------------|------------|------------|------------|
| Billion Laughs            | Vulnerable | Vulnerable | Vulnerable | Vulnerable | Vulnerable |
| Quadratic Blowup          | Vulnerable | Vulnerable | Vulnerable | Vulnerable | Vulnerable |
| External Entity Expansion | Safe       | Safe       | Safe       | Safe       | Safe       |
| DTD Retrieval             | Safe       | Safe       | Safe       | Safe       | Safe       |
| Decompression Bomb        | Safe       | Safe       | Safe       | Safe       | Vulnerable |

To protect your application from the applicable attacks, [two packages](https://docs.python.org/3/library/xml.html#the-defusedxml-and-defusedexpat-packages) exist to help you sanitize your input and protect your application against DDoS and remote attacks.

## Semgrep Rules

[Semgrep](https://semgrep.dev/) is a command-line tool for offline static analysis. Use pre-built or custom rules to enforce code and security standards in your codebase.

### Java

Below are the rules for different XML parsers in Java

#### Digester

Identifying XXE vulnerability in the `org.apache.commons.digester3.Digester` library
Rule can be played here [https://semgrep.dev/s/salecharohit:xxe-Digester](https://semgrep.dev/s/salecharohit:xxe-Digester)

#### DocumentBuilderFactory

Identifying XXE vulnerability in the `javax.xml.parsers.DocumentBuilderFactory` library
Rule can be played here [https://semgrep.dev/s/salecharohit:xxe-dbf](https://semgrep.dev/s/salecharohit:xxe-dbf)

#### SAXBuilder

Identifying XXE vulnerability in the `org.jdom2.input.SAXBuilder` library
Rule can be played here [https://semgrep.dev/s/salecharohit:xxe-saxbuilder](https://semgrep.dev/s/salecharohit:xxe-saxbuilder)

#### SAXParserFactory

Identifying XXE vulnerability in the `javax.xml.parsers.SAXParserFactory` library
Rule can be played here [https://semgrep.dev/s/salecharohit:xxe-SAXParserFactory](https://semgrep.dev/s/salecharohit:xxe-SAXParserFactory)

#### SAXReader

Identifying XXE vulnerability in the `org.dom4j.io.SAXReader` library
Rule can be played here [https://semgrep.dev/s/salecharohit:xxe-SAXReader](https://semgrep.dev/s/salecharohit:xxe-SAXReader)

#### XMLInputFactory

Identifying XXE vulnerability in the `javax.xml.stream.XMLInputFactory` library
Rule can be played here [https://semgrep.dev/s/salecharohit:xxe-XMLInputFactory](https://semgrep.dev/s/salecharohit:xxe-XMLInputFactory)

#### XMLReader

Identifying XXE vulnerability in the `org.xml.sax.XMLReader` library
Rule can be played here [https://semgrep.dev/s/salecharohit:xxe-XMLReader](https://semgrep.dev/s/salecharohit:xxe-XMLReader)

## References

- [XXE by InfoSecInstitute](https://resources.infosecinstitute.com/identify-mitigate-xxe-vulnerabilities/)
- [OWASP Top 10-2017 A4: XML External Entities (XXE)](https://owasp.org/www-project-top-ten/OWASP_Top_Ten_2017/Top_10-2017_A4-XML_External_Entities_%28XXE%29)
- [Timothy Morgan's 2014 paper: "XML Schema, DTD, and Entity Attacks"](https://vsecurity.com//download/papers/XMLDTDEntityAttacks.pdf)
- [FindSecBugs XXE Detection](https://find-sec-bugs.github.io/bugs.htm#XXE_SAXPARSER)
- [XXEbugFind Tool](https://github.com/ssexxe/XXEBugFind)
- [Testing for XML Injection](https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/07-Input_Validation_Testing/07-Testing_for_XML_Injection.html)
