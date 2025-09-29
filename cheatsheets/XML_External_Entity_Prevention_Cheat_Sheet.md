
# XML External Entity (XXE) Prevention Cheat Sheet

## Table of Contents

1. Introduction
2. Threat overview and XXE types
3. Core mitigations (applied across languages)
4. Secure-by-default parser configuration checklist
5. Language-specific guidance and examples
6. Vulnerable vs Safe code snippets (per language)
7. Testing and validation
8. Static analysis / Semgrep
9. Deployment & infrastructure considerations
10. Monitoring, logging & incident response
11. Migration notes
12. References & further reading
13. Appendix: Quick reference (one-page)

## 1. Introduction

XML External Entity (XXE) vulnerabilities arise when an XML parser processes external entities that can be exploited by attackers.  

This cheat sheet covers how to securely configure XML parsers, provides language-specific guidance, and lists secure coding examples.

## 2. Threat overview and XXE types

- **In-band XXE (classic):** An attacker can read local files, perform SSRF, or disclose internal data.
- **Blind XXE:** Exploitation occurs without immediate feedback.
- **Out-of-band XXE:** Triggers an external interaction (DNS, HTTP) controlled by the attacker.
- **File disclosure (local file read)**
- **Server-side request forgery (SSRF)**
- **Denial of service (e.g., Billion Laughs attack)**

## 3. Core mitigations (applied across languages)

1. Disable DTD processing / external entity resolution.  
2. Use secure parser APIs or hardened configurations.  
3. Validate and sanitize XML input.  
4. Avoid using XML where simpler formats suffice (e.g., JSON).  
5. Apply principle of least privilege to XML parsing.  

## 4. Secure-by-default parser configuration checklist

- Disable external entity processing.  
- Avoid loading external DTDs.  
- Apply strict schema validation if required.  
- Ensure parser libraries are up-to-date.  
- Isolate XML processing in sandboxed environments if possible.

## 5. Language-specific guidance and examples

### Vulnerable example (do NOT use)

```java
DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
DocumentBuilder db = dbf.newDocumentBuilder();
Document doc = db.parse(xmlFile);
```

#### Safe example — DocumentBuilderFactory (recommended)

```java
DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
DocumentBuilder db = dbf.newDocumentBuilder();
Document doc = db.parse(xmlFile);
```

#### Safe example — XMLInputFactory (StAX)

```java
XMLInputFactory xif = XMLInputFactory.newInstance();
xif.setProperty(XMLInputFactory.SUPPORT_DTD, false);
xif.setProperty("javax.xml.stream.isSupportingExternalEntities", false);
```

#### TransformerFactory and Validator

```java
TransformerFactory tf = TransformerFactory.newInstance();
tf.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
```

#### Safe example — XmlReaderSettings

```csharp
XmlReaderSettings settings = new XmlReaderSettings();
settings.DtdProcessing = DtdProcessing.Prohibit;
XmlReader reader = XmlReader.Create("file.xml", settings);
```

#### Safe example — XDocument with XmlReader

```csharp
XDocument doc;
using (XmlReader reader = XmlReader.Create("file.xml", settings)) {
    doc = XDocument.Load(reader);
}
```

#### Safe example — defusedxml.ElementTree

```python
from defusedxml import ElementTree as ET
tree = ET.parse('file.xml')
```

#### Safe example — lxml with disabled resolve/entities

```python
from lxml import etree
parser = etree.XMLParser(resolve_entities=False)
tree = etree.parse('file.xml', parser)
```

#### Vulnerable example

```php
$xml = simplexml_load_file("file.xml");
```

#### Safe example

```php
$xml = simplexml_load_file("file.xml", "SimpleXMLElement", LIBXML_NOENT | LIBXML_DTDLOAD);
```

#### xml2js (example)

```javascript
const xml2js = require('xml2js');
const parser = new xml2js.Parser({ explicitArray: false });
```

#### fast-xml-parser (example)

```javascript
const { XMLParser } = require('fast-xml-parser');
const parser = new XMLParser({ ignoreAttributes: false });
```

#### vulnerable - REXML (do not use for untrusted input)

```ruby
require 'rexml/document'
doc = REXML::Document.new(xml_string)
```

#### safe - Nokogiri

```ruby
require 'nokogiri'
doc = Nokogiri::XML(xml_string) { |config| config.strict.nonet }
```

- Use `xmlReadMemory`/`xmlReadFile` with `XML_PARSE_NOENT` disabled in C.  

#### Xerces-C++

```cpp
xercesc::XercesDOMParser parser;
parser.setExternalEntityHandling(XercesDOMParser::XEH_IGNORE_SEMANTICS);
```

#### Adobe ColdFusion (example)

```cfml
<cfxml variable="xmlDoc" suppressExternalEntities="yes">
```

#### Lucee

```cfml
<cfxml variable="xmlDoc" suppressExternalEntities="yes">
```

## 6. Vulnerable vs Safe code snippets (per language)

(Include all examples above in a summary table format if desired.)

## 7. Testing and validation

- Validate parsing behavior against crafted XXE payloads.  
- Use automated tools to detect XXE risks.

## 8. Static analysis / Semgrep

- Semgrep rules for detecting vulnerable XML parsing.  
- Integrate into CI/CD pipelines for continuous protection.

## 9. Deployment & infrastructure considerations

- Disable network access for XML parsing if not required.  
- Apply firewall rules to limit external requests triggered by parsers.

## 10. Monitoring, logging & incident response

- Log parsing errors and potential entity processing attempts.  
- Alert on abnormal outbound requests during XML processing.

## 11. Migration notes

- Review legacy XML parsers and update to secure configurations.  
- Deprecate old libraries known to allow XXE by default.

## 12. References & further reading

- OWASP XXE Prevention Cheat Sheet  
- Language-specific secure XML parsing guides  

## 13. Appendix: Quick reference (one-page)

1. Disable DTDs / DOCTYPEs
2. Disable external entities
3. Use secure parser features
4. Validate input strictly
5. Avoid unnecessary XML features
6. Test with malicious payloads
