# XML External Entity Prevention Cheat Sheet

## Introduction

XML External Entity (XXE) injection occurs when an XML processor resolves an external entity from untrusted input. This can expose local files, cause server-side request forgery (SSRF), or exhaust resources. [CWE-611](https://cwe.mitre.org/data/definitions/611.html) describes the weakness; this cheat sheet gives parser-specific controls to prevent it.

## General Guidance

**Disable document type definitions (DTDs) whenever possible.** Reject DOCTYPE declarations if the parser supports it. If your application needs DTDs, disable external entity resolution and external DTD loading, and limit entity expansion.

- Keep XInclude disabled unless explicitly required; it can load resources independently of DTDs.
- Restrict external access during schema validation and style sheet processing as well as XML parsing.
- Treat an unsupported security setting as a configuration failure. Do not continue processing untrusted XML with partial hardening.

Controls and defaults vary by parser; see the language-specific guidance below and, for Java, the [JAXP Security Guide](https://docs.oracle.com/en/java/javase/25/security/java-api-xml-processing-jaxp-security-guide.html). Preventing XXE does not prevent every XML denial-of-service attack. See the [XML Security Cheat Sheet](XML_Security_Cheat_Sheet.md#xml-entity-expansion) for entity expansion and other XML resource risks.

## C/C++

### libxml2

The Enum [xmlParserOption](https://gnome.pages.gitlab.gnome.org/libxml2/html/parser_8h.html) should not have the following options defined:

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

Per [this blog post](https://www.hoyahaxa.com/2022/11/on-coldfusion-xxe-and-other-xml-attacks.html), both Adobe ColdFusion and Lucee have built-in mechanisms to disable support for external XML entities.

### Adobe ColdFusion

As of ColdFusion 2018 Update 14 and ColdFusion 2021 Update 4, all native ColdFusion functions that process XML have a XML parser argument that disables support for external XML entities. Since there is no global setting that disables external entities, developers must ensure that every XML function call uses the correct security options.

From the [documentation for the XmlParse() function](https://guides.adobe.com/coldfusion/en/docs/cfml-reference/xmlparse.html), you can disable XXE with the code below:

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

The examples below use the built-in Java API for XML Processing (JAXP) implementations on Java 9 or later. `newDefaultInstance()` (`newDefaultFactory()` for StAX) selects the built-in implementation instead of a provider selected through the [JAXP lookup mechanism](https://docs.oracle.com/en/java/javase/25/docs/api/java.xml/module-summary.html#LookupMechanism). For other providers, see [implementation differences](#other-providers-and-required-dtds).

These are illustrative configuration fragments. The application opens and closes the input streams, supplies trusted schemas and style sheets, and handles exceptions. **Stop processing if any required security setting fails; do not catch the exception and continue parsing.** Pass streams rather than untrusted filenames or URLs: external-entity controls do not restrict access to the initial resource passed directly to a parsing or processing API.

### Secure configuration by API

| API | Recommended approach |
| --- | --- |
| [`DocumentBuilderFactory`](#documentbuilderfactory-dom) | Reject DOCTYPE declarations before building a document tree |
| [`SAXParserFactory` / `XMLReader`](#saxparserfactory-and-xmlreader) | Reject DOCTYPE declarations; parse through the configured reader |
| [`XMLInputFactory`](#xmlinputfactory-stax) | Disable DTD processing and external entities |
| [`TransformerFactory`](#transformerfactory-xslt) | Deny external access before compiling the style sheet |
| [`SchemaFactory` / `Validator`](#schemafactory-and-validator) | Deny external access during compilation and validation |
| [`XPath`](#xpath) | Evaluate against a document parsed with a hardened builder |
| [`Unmarshaller`](#jaxb-unmarshaller) | Supply a hardened StAX reader |

#### DocumentBuilderFactory (DOM)

For Document Object Model (DOM) parsing, [reject DOCTYPE declarations](https://xerces.apache.org/xerces2-j/features.html#disallow-doctype-decl) and leave XInclude disabled.

``` java
DocumentBuilderFactory dbf = DocumentBuilderFactory.newDefaultInstance();
dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
dbf.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);

DocumentBuilder builder = dbf.newDocumentBuilder();
Document doc = builder.parse(untrustedStream);
```

[`setExpandEntityReferences(false)`](https://docs.oracle.com/en/java/javase/25/docs/api/java.xml/javax/xml/parsers/DocumentBuilderFactory.html#setExpandEntityReferences(boolean)) controls the representation of entity references in the tree. Do not use it as a substitute for blocking external resources.

#### SAXParserFactory and XMLReader

For Simple API for XML (SAX) parsing, reject DOCTYPE declarations on the factory before creating the reader.

``` java
SAXParserFactory spf = SAXParserFactory.newDefaultInstance();
spf.setNamespaceAware(true);
spf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
spf.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);

XMLReader reader = spf.newSAXParser().getXMLReader();
reader.setContentHandler(handler);  // application's SAX content handler
reader.parse(new InputSource(untrustedStream));
```

#### XMLInputFactory (StAX)

For Streaming API for XML (StAX), set both [DTD and external-entity properties](https://docs.oracle.com/en/java/javase/25/docs/api/java.xml/javax/xml/stream/XMLInputFactory.html). DTD processing defaults to enabled; the external-entity default is unspecified.

``` java
XMLInputFactory xif = XMLInputFactory.newDefaultFactory();
xif.setProperty(XMLInputFactory.SUPPORT_DTD, false);
xif.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, false);
xif.setXMLResolver((publicId, systemId, baseURI, namespace) -> {
    throw new XMLStreamException("External references are not allowed");
});
XMLStreamReader xsr = xif.createXMLStreamReader(untrustedStream);
```

Disabling DTD processing does not necessarily reject the DOCTYPE declaration. StAX does not support `FEATURE_SECURE_PROCESSING`; use the provider's processing limits when DTDs are required.

#### TransformerFactory (XSLT)

XSL Transformations (XSLT) can load resources through style sheet imports, includes and `document()`, independently of external entities. For a trusted application-owned style sheet that needs no external resources, set [both external-access restrictions](https://docs.oracle.com/en/java/javase/25/docs/api/java.xml/javax/xml/transform/TransformerFactory.html#setAttribute(java.lang.String,java.lang.Object)) before compilation:

``` java
TransformerFactory factory = TransformerFactory.newDefaultInstance();
factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");
factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_STYLESHEET, "");

Transformer transformer =
        factory.newTransformer(new StreamSource(trustedStylesheetStream));
transformer.transform(new StreamSource(untrustedStream), result);
```

This configuration limits internal entity expansion but is not a sandbox for untrusted style sheets. Choose the style sheet in application code; do not trust a style sheet reference supplied by the input document. For other providers or required dependencies, apply the [resource policy](#external-resources-for-transformations-and-validation) below.

#### SchemaFactory and Validator

Schema compilation and validation can each load external resources. For a trusted application-owned schema that needs no external resources, [restrict access on the factory before compiling the schema](https://docs.oracle.com/en/java/javase/25/docs/api/java.xml/javax/xml/validation/SchemaFactory.html#setProperty(java.lang.String,java.lang.Object)); these restrictions also apply during validation:

``` java
SchemaFactory sf = SchemaFactory.newDefaultInstance();
sf.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
sf.setProperty(XMLConstants.ACCESS_EXTERNAL_DTD, "");
sf.setProperty(XMLConstants.ACCESS_EXTERNAL_SCHEMA, "");
Schema schema = sf.newSchema(new StreamSource(trustedSchemaStream));

Validator validator = schema.newValidator();
validator.validate(new StreamSource(untrustedStream));
```

If you install a resolver, configure it on the factory **and each validator**: [validators do not inherit the factory's resolver](https://docs.oracle.com/en/java/javase/25/docs/api/java.xml/javax/xml/validation/SchemaFactory.html#setResourceResolver(org.w3c.dom.ls.LSResourceResolver)). The same applies to `ValidatorHandler`.

#### XPath

Avoid the [`InputSource` overloads of `XPath.evaluate`](https://docs.oracle.com/en/java/javase/25/docs/api/java.xml/javax/xml/xpath/XPath.html#evaluate(java.lang.String,org.xml.sax.InputSource)), which parse the document internally. Use the [hardened DOM builder](#documentbuilderfactory-dom) and evaluate against the resulting document:

``` java
Document doc = builder.parse(untrustedStream);
XPath xpath = XPathFactory.newDefaultInstance().newXPath();
NodeList nodes = (NodeList) xpath.evaluate("//user/name", doc, XPathConstants.NODESET);
```

#### JAXB Unmarshaller

For Java Architecture for XML Binding (JAXB), pass the reader from the [StAX example](#xmlinputfactory-stax) to [`Unmarshaller.unmarshal`](https://jakarta.ee/specifications/xml-binding/4.0/apidocs/jakarta.xml.bind/jakarta/xml/bind/Unmarshaller.html#unmarshal(javax.xml.stream.XMLStreamReader)). Passing raw XML instead delegates parser configuration to the JAXB provider.

``` java
Object result = jaxbContext.createUnmarshaller().unmarshal(xsr);
```

### Other providers and required DTDs

`newInstance()` can select a third-party provider whose settings differ. Verify the provider's documented controls and fail if a required setting is unsupported. Boolean features use `setFeature`; external-access properties use `setAttribute` on a DOM factory and `setProperty` on a SAX parser or reader.

If internal DTDs are required, install an `EntityResolver` on the DOM builder or SAX reader that throws `SAXException` for external references. Returning `null` delegates resolution to the parser. Set these [Xerces/SAX features](https://xerces.apache.org/xerces2-j/features.html#external-general-entities) to `false` instead of rejecting DOCTYPE:

- `http://xml.org/sax/features/external-general-entities`
- `http://xml.org/sax/features/external-parameter-entities`
- `http://apache.org/xml/features/nonvalidating/load-external-dtd`

Keep XInclude disabled. The last feature only controls non-validating parsing; DTD validation needs an explicit policy for any required external DTD. Set applicable `ACCESS_EXTERNAL_*` properties to `""` when supported. A resolver does not limit internal entity expansion: enable [`FEATURE_SECURE_PROCESSING`](https://docs.oracle.com/en/java/javase/25/docs/api/java.xml/javax/xml/XMLConstants.html#FEATURE_SECURE_PROCESSING) where supported and configure the provider's processing limits. Secure processing alone is not a portable replacement for external-access restrictions.

When using a SAX resolver, call `reader.parse(...)` directly. [`SAXParser.parse(source, DefaultHandler)` replaces the reader's resolver](https://github.com/openjdk/jdk/blob/6c48f4ed707bf0b15f9b6098de30db8aae6fa40f/src/java.xml/share/classes/javax/xml/parsers/SAXParser.java#L389-L392) with the supplied handler.

### External resources for transformations and validation

For other transformation or validation providers, supply XML, schemas and style sheets through a [`SAXSource`](https://docs.oracle.com/en/java/javase/25/docs/api/java.xml/javax/xml/transform/sax/SAXSource.html) with a hardened, namespace-aware `XMLReader`. Separately install a rejecting `URIResolver` for transformations or `LSResourceResolver` for schemas. The input parser's settings do not control style sheet or schema dependencies.

When external dependencies are required, use a [catalog with `RESOLVE=strict`](https://docs.oracle.com/en/java/javase/25/docs/api/java.xml/javax/xml/catalog/CatalogFeatures.html) to map approved identifiers to local resources, or an allowlisting resolver. Reject unapproved identifiers; returning `null` delegates to default resolution. External-access properties restrict protocols, not individual resources: allowing `https` is not a resource allowlist. Resources returned by your resolver remain your responsibility.

Apply the policy before compilation and during processing. Set the [`URIResolver` on the transformer factory before `newTransformer`](https://docs.oracle.com/en/java/javase/25/docs/api/java.xml/javax/xml/transform/TransformerFactory.html#setURIResolver(javax.xml.transform.URIResolver)); transformers use it by default. For validation, install the resolver on the factory and every validator as described above.

### Parsers that wrap a JAXP parser

Supply wrappers with a hardened parser and check whether they replace its resolver:

| Library | Configuration |
| --- | --- |
| dom4j | Supply the reader with [`SAXReader.setXMLReader`](https://javadoc.io/doc/org.dom4j/dom4j/latest/org/dom4j/io/SAXReader.html#setXMLReader(org.xml.sax.XMLReader)) and set the rejecting resolver with `SAXReader.setEntityResolver`; [dom4j replaces the reader's resolver](https://github.com/dom4j/dom4j/blob/8db3742e13860c6767971867458073e8dd0fa1d1/src/main/java/org/dom4j/io/SAXReader.java#L464-L476) |
| JDOM | Supply the reader through [`SAXBuilder(XMLReaderJDOMFactory)`](https://www.jdom.org/docs/apidocs/org/jdom2/input/SAXBuilder.html#SAXBuilder-org.jdom2.input.sax.XMLReaderJDOMFactory-) |
| Commons Digester | Supply a hardened reader and call `Digester.setEntityResolver` before parsing; [Digester replaces the reader's resolver](https://github.com/apache/commons-digester/blob/0e6d183e1edba72b5d78208307c82f71bfdfb7ad/commons-digester3-core/src/main/java/org/apache/commons/digester3/Digester.java#L1869-L1876) |

### Oracle DOM Parser

For Oracle XML Developer's Kit (`oracle.xml.parser.v2`), call [`setSecureProcessing()`](https://docs.oracle.com/en/database/oracle/oracle-database/21/adxdk/security-considerations-oracle-xml-developers-kit.html) on the DOM or SAX parser. It disables entity resolution and limits expansion. On its JAXP binding, enable `FEATURE_SECURE_PROCESSING`.

### java.beans.XMLDecoder

Do not use `XMLDecoder` with untrusted input. Blocking external entities does not remove its [deserialization risk](Deserialization_Cheat_Sheet.md#other-deserialization-libraries-and-formats).

### Secure JAXP factory sources

[Apache Commons Secure XML](https://commons.apache.org/proper/commons-secure-xml/) provides preconfigured factories. Check its [threat model](https://github.com/apache/commons-secure-xml/blob/main/src/site/markdown/threat_model.md) for supported runtimes and limits. Its protections do not cover URIs passed directly to parsing APIs, parsers created outside the library, or untrusted resources your resolver chooses to supply. Do not loosen its reserved security settings.

## .NET

**Up-to-date information for XXE injection in .NET is taken directly from the [web application of unit tests by Dean Fleming](https://github.com/deanf1/dotnet-security-unit-tests), which covers all currently supported .NET XML parsers, and has test cases that demonstrate when they are safe from XXE injection and when they are not, but these tests are only with injection from file and not direct DTD (used by DoS attacks).**

For DoS attacks using a direct DTD (such as the [Billion laughs attack](https://en.wikipedia.org/wiki/Billion_laughs_attack)), a [separate testing application from Josh Grossman at Bounce Security](https://github.com/BounceSecurity/BillionLaughsTester) has been created to verify that .NET >=4.5.2 is safe from these attacks.

Previously, this information was based on some older articles which may not be 100% accurate including:

- [James Jardine's excellent .NET XXE article](https://www.jardinesoftware.net/2016/05/26/xxe-and-net/).
- [Guidance from Microsoft on how to prevent XXE and XML Denial of Service in .NET](https://learn.microsoft.com/en-us/archive/msdn-magazine/2009/november/xml-denial-of-service-attacks-and-defenses).

### Overview of .NET Parser Safety Levels

**Below is an overview of all supported .NET XML parsers and their default safety levels. More details about each parser are included below.**

#### XDocument (LINQ to XML) default safety levels

This parser is protected from external entities at .NET Framework version 4.5.2 and protected from Billion Laughs at version 4.5.2 or greater, but it is uncertain if this parser is protected from Billion Laughs before version 4.5.2.

#### XmlDocument, XmlTextReader, XPathNavigator default safety levels

These parsers are vulnerable to external entity attacks and Billion Laughs at versions below version 4.5.2 but protected at versions equal or greater than 4.5.2.

#### XmlDictionaryReader, XmlNodeReader, XmlReader default safety levels

These parsers are not vulnerable to external entity attacks or Billion Laughs before or after version 4.5.2. Also, at or greater than versions ≥4.5.2, these libraries won't even process the in-line DTD by default. Even if you change the default to allow processing a DTD, if a DoS attempt is performed an exception will still be thrown as documented above.

### ASP.NET

ASP.NET applications ≥ .NET 4.5.2 must also ensure setting the `<httpRuntime targetFramework="..." />` in their `Web.config` to ≥4.5.2 or risk being vulnerable regardless of the actual .NET version. Omitting this tag will also result in unsafe-by-default behavior.

For the purpose of understanding the version thresholds above, the effective .NET Framework version for an ASP.NET application is either the .NET version the application was built with or the httpRuntime's `targetFramework` (Web.config), **whichever is lower**.

This configuration tag should not be confused with a similar configuration tag: `<compilation targetFramework="..." />` or the assemblies / projects targetFramework, which are **not** sufficient for achieving secure-by-default behavior as described above.

### LINQ to XML

**Both the `XElement` and `XDocument` objects in the `System.Xml.Linq` library are safe from XXE injection from external file and DoS attack by default.** `XElement` parses only the elements within the XML file, so DTDs are ignored altogether. `XDocument` has XmlResolver [disabled by default](https://learn.microsoft.com/en-us/dotnet/standard/linq/linq-xml-security) so it's safe from SSRF. While DTDs are [enabled by default](https://github.com/microsoft/referencesource/blob/main/System.Xml.Linq/System/Xml/Linq/XLinq.cs#L1986-L1993), from Framework versions ≥4.5.2, it is **not** vulnerable to DoS as noted but it may be vulnerable in earlier Framework versions. For more information, see [Microsoft's guidance on how to prevent XXE and XML Denial of Service in .NET](https://learn.microsoft.com/en-us/archive/msdn-magazine/2009/november/xml-denial-of-service-attacks-and-defenses)

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

`XmlDocument` can become unsafe if you create your own nonnull `XmlResolver` with default or unsafe settings. If you need to enable DTD processing, instructions on how to do so safely are described in detail in the [referenced MSDN article](https://learn.microsoft.com/en-us/archive/msdn-magazine/2009/november/xml-denial-of-service-attacks-and-defenses).

### XmlNodeReader

`System.Xml.XmlNodeReader` objects are safe by default and will ignore DTDs even when constructed with an unsafe parser or wrapped in another unsafe parser.

### XmlReader

`System.Xml.XmlReader` objects are safe by default.

They are set by default to have their ProhibitDtd property set to false in .NET Framework versions 4.0 and earlier, or their `DtdProcessing` property set to Prohibit in .NET versions 4.0 and later.

Additionally, in .NET versions 4.5.2 and later, the `XmlReaderSettings` belonging to the `XmlReader` has its `XmlResolver` set to null by default, which provides an additional layer of safety.

Therefore, `XmlReader` objects will only become unsafe in version 4.5.2 and up if both the `DtdProcessing` property is set to Parse and the `XmlReaderSetting`'s `XmlResolver` is set to a nonnull XmlResolver with default or unsafe settings. If you need to enable DTD processing, instructions on how to do so safely are described in detail in the [referenced MSDN article](https://learn.microsoft.com/en-us/archive/msdn-magazine/2009/november/xml-denial-of-service-attacks-and-defenses).

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

[The source code for this method is here.](https://github.com/microsoft/referencesource/blob/main/System.Xml/System/Xml/Xslt/XslCompiledTransform.cs)

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

A description of how to abuse this in PHP is presented in a good [SensePost article](https://sensepost.com/blog/2014/revisting-xxe-and-abusing-protocols/) describing a cool PHP based XXE vulnerability that was fixed in Facebook.

## Python

The Python 3 official documentation contains a section on [xml vulnerabilities](https://docs.python.org/3/library/xml.html#xml-vulnerabilities). As of the 1st January 2020 Python 2 is no longer supported, however the Python website still contains [some legacy documentation](https://docs.python.org/2/library/xml.html#xml-vulnerabilities).

The table below shows you which various XML parsing modules in Python 3 are vulnerable to certain XXE attacks.

| Attack Type               | sax        | etree      | minidom    | pulldom    | xmlrpc     |
|---------------------------|------------|------------|------------|------------|------------|
| Billion Laughs            | Vulnerable | Vulnerable | Vulnerable | Vulnerable | Vulnerable |
| Quadratic Blowup          | Vulnerable | Vulnerable | Vulnerable | Vulnerable | Vulnerable |
| External Entity Expansion | Safe       | Safe       | Safe       | Safe       | Safe       |
| DTD Retrieval             | Safe       | Safe       | Safe       | Safe       | Safe       |
| Decompression Bomb        | Safe       | Safe       | Safe       | Safe       | Vulnerable |

To protect your application from the applicable attacks, the [defusedxml](https://github.com/tiran/defusedxml) package exists to help you sanitize your input and protect your application against DDoS and remote attacks.

## Semgrep Rules

[Semgrep](https://semgrep.dev/) is a command-line tool for offline static analysis. Use pre-built or custom rules to enforce code and security standards in your codebase.

### Java

Below are the rules for different XML parsers in Java

#### DocumentBuilderFactory

Identifying XXE vulnerability in the `javax.xml.parsers.DocumentBuilderFactory` library.
The official registry rule is [documentbuilderfactory-disallow-doctype-decl-missing](https://semgrep.dev/r/java.lang.security.audit.xxe.documentbuilderfactory-disallow-doctype-decl-missing.documentbuilderfactory-disallow-doctype-decl-missing).

#### SAXParserFactory

Identifying XXE vulnerability in the `javax.xml.parsers.SAXParserFactory` library.
The official registry rule is [saxparserfactory-disallow-doctype-decl-missing](https://semgrep.dev/r/java.lang.security.audit.xxe.saxparserfactory-disallow-doctype-decl-missing.saxparserfactory-disallow-doctype-decl-missing).

#### XMLInputFactory

Identifying XXE vulnerability in the `javax.xml.stream.XMLInputFactory` library.
The official registry rule is [xmlinputfactory-possible-xxe](https://semgrep.dev/r/java.lang.security.xmlinputfactory-possible-xxe.xmlinputfactory-possible-xxe).

## References

- [OWASP Top 10-2017 A4: XML External Entities (XXE)](https://owasp.org/www-project-top-ten/2017/A4_2017-XML_External_Entities_%28XXE%29.html)
- [Timothy Morgan's 2014 paper: "XML Schema, DTD, and Entity Attacks"](https://dl.packetstormsecurity.net/papers/general/XMLDTDEntityAttacks.pdf)
- [FindSecBugs XXE Detection](https://find-sec-bugs.github.io/bugs.htm#XXE_SAXPARSER)
- [XXEbugFind Tool](https://github.com/ssexxe/XXEBugFind)
- [Testing for XML Injection](https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/07-Input_Validation_Testing/07-Testing_for_XML_Injection.html)
