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

1. Disable DTDs (doctypes) completely where not required.
2. Disable external entity resolution (`XmlResolver` in .NET, `EntityResolver` in Java, `libxml` loader in PHP, etc.).
3. Set secure processing features (e.g., `XMLConstants.FEATURE_SECURE_PROCESSING` in Java).
4. Avoid permissive, legacy parsers (e.g., `java.beans.XMLDecoder`, REXML unsafe modes, old PHP libxml behavior).
5. Use safe libraries or hardened wrappers (e.g., Python `defusedxml`, .NET secure defaults).
6. Validate and sanitize XML input where possible: apply schema validation with safe schema factories and limit allowed elements/attributes.
7. Implement input size limits and resource quotas to prevent DoS (maximum file size, maximum entity expansion depth if available).
8. Use a no-op or safe EntityResolver to force entity resolution to be inert when parser requires an implementation.
9. Prefer streaming parsers with explicit safe settings (StAX, XmlReader, SAX) rather than forgiving fully in-memory DOMs when processing untrusted input.
10. Use network controls (egress filtering, internal DNS monitoring) to detect/prevent OOB callbacks.

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

### Java (JAXP, SAX, StAX, Transformer, Validator)

#### Vulnerable example (do NOT use)
```java
import javax.xml.parsers.DocumentBuilderFactory;
DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
DocumentBuilder db = dbf.newDocumentBuilder();
Document doc = db.parse(new File("input.xml"));
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
        dbf.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
        try { dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true); } catch (Exception ex) {}
        dbf.setXIncludeAware(false);
        dbf.setExpandEntityReferences(false);
        try {
            dbf.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");
            dbf.setAttribute(XMLConstants.ACCESS_EXTERNAL_SCHEMA, "");
        } catch (IllegalArgumentException ignore) {}
        DocumentBuilder builder = dbf.newDocumentBuilder();
        builder.setEntityResolver((publicId, systemId) -> new InputSource(new StringReader("")));
        return builder.parse(xmlFile);
    }
}
```

#### Safe example — XMLInputFactory (StAX)
```java
import javax.xml.stream.XMLInputFactory;

XMLInputFactory xif = XMLInputFactory.newFactory();
xif.setProperty(XMLInputFactory.SUPPORT_DTD, false);
xif.setProperty("javax.xml.stream.isSupportingExternalEntities", false);
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

### .NET (Modern guidance for .NET 6/7)

#### Safe example — XmlReaderSettings
```csharp
using System.Xml;

var settings = new XmlReaderSettings
{
    DtdProcessing = DtdProcessing.Prohibit,
    XmlResolver = null,
    MaxCharactersFromEntities = 1024
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

### Python (defusedxml, lxml)

```python
from defusedxml.ElementTree import parse

with open('input.xml', 'rb') as f:
    tree = parse(f)
```

```python
from lxml import etree

parser = etree.XMLParser(resolve_entities=False, load_dtd=False, no_network=True)
tree = etree.parse('input.xml', parser)
```

### PHP (libxml / SimpleXML)

```php
libxml_disable_entity_loader(true);
$dom = new DOMDocument();
$dom->loadXML(file_get_contents('input.xml'), LIBXML_NONET);
$xml = simplexml_load_string(file_get_contents('input.xml'), null, LIBXML_NONET);
```

### JavaScript / Node.js (xml2js, fast-xml-parser)

```javascript
const fs = require('fs');
const xml2js = require('xml2js');

const parser = new xml2js.Parser({explicitCharkey: false});
const xml = fs.readFileSync('input.xml', 'utf8');
parser.parseString(xml, function(err, result) {});
```

```javascript
const { XMLParser } = require('fast-xml-parser');
const parser = new XMLParser({ ignoreAttributes: false, allowBooleanAttributes: true });
```

### Ruby (REXML, Nokogiri)

```ruby
require 'nokogiri'
xml = File.read('input.xml')
doc = Nokogiri::XML(xml, nil, nil, Nokogiri::XML::ParseOptions::NONET)
```

### C / C++ (libxml2, Xerces)

```c
xmlReadFile("input.xml", NULL, XML_PARSE_NONET);
```

```cpp
parser->setDisableDefaultEntityResolution(true);
parser->setFeature(XMLUni::fgXercesDisableDefaultEntityResolution, true);
```

### ColdFusion / Lucee

```cfml
<cfset parserOptions = structNew()>
<cfset parserOptions.ALLOWEXTERNALENTITIES = false>
<cfscript>
  doc = XmlParse(FileRead("input.xml"), false, parserOptions);
</cfscript>
```

```cfml
this.xmlFeatures = {
    externalGeneralEntities: false,
    secure: true,
    disallowDoctypeDecl: true
};
```

---
## 6. Vulnerable vs Safe code snippets (per language)

- Vulnerable: parsing XML with default DOM parsers without disabling DTDs or resolvers.
- Safe: create parser settings that explicitly disallow DTDs, set resolvers to null/no-op, and use nonet flags.

---
## 7. Testing and validation

- Burp Suite / Burp Collaborator
- OWASP ZAP
- XXE-specific scanners
- Custom local listeners (netcat) and OOB endpoints

**File disclosure:**
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<foo>&xxe;</foo>
```

**Billion Laughs DoS:**
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

---
## 8. Static analysis / Semgrep

- Create rules to detect unsafe parser usage (Java, .NET, PHP, Python, etc.)
- Example: `DocumentBuilderFactory.newInstance()` without secure `setFeature`

---
## 9. Deployment & infrastructure considerations

- Egress filtering
- Internal DNS monitoring
- WAF
- Rate limits and parsing quotas

---
## 10. Monitoring, logging & incident response

- Log parse-time exceptions
- Alert on unexpected outbound requests
- Preserve logs and payloads for suspected XXE

---
## 11. Migration notes

- Remove references to deprecated projects
- Mark iOS < 7 guidance as deprecated
- Update examples to modern runtimes

---
## 12. References & further reading

- OWASP: XML External Entity (XXE) Prevention
- DefusedXML Python docs
- Microsoft: XML security guidance (.NET)
- libxml2 and Xerces documentation

---
## 13. Appendix: Quick reference (one-page)

**Always do these three things for untrusted XML:**
1. Disable DTDs / DOCTYPEs
2. Disable external entity resolution
3. Use streaming secure parsers and add size/resource limits
