# XML Security Cheat Sheet

## Introduction

While the specifications for XML and XML schemas provide you with the tools needed to protect XML applications, they also include multiple security flaws. They can be exploited to perform multiple types of attacks, including file retrieval, server side request forgery, port scanning, and brute forcing. This cheat sheet will make you aware of how attackers can exploit the different possibilities in XML used in libraries and software using two possible attack surfaces:

- **Malformed XML Documents**: Exploiting vulnerabilities that occur when applications encounter XML documents that are not well-formed.
- **Invalid XML Documents**: Exploiting vulnerabilities that occur when documents that do not have the expected structure.

## Dealing with malformed XML documents

### Definition of a malformed XML document

 If an XML document does not follow the W3C XML specification's definition of a well-formed document, it is considered "malformed." **If an XML document is malformed, the XML parser will detect a fatal error, it should stop execution, the document should not undergo any additional processing, and the application should display an error message.** A malformed document can include one or more of the following problems: a missing ending tag, the order of elements into a nonsensical structure, introducing forbidden characters, and so on.

### Handling malformed XML documents

**To deal with malformed documents, developers should use an XML processor that follows W3C specifications and does not take significant additional time to process malformed documents.** In addition, they should only use well-formed documents, validate the contents of each element, and process only valid values within predefined boundaries.

#### Malformed XML documents require extra time

**A malformed document may affect the consumption of Central Processing Unit (CPU) resources.** In certain scenarios, the amount of time required to process malformed documents may be greater than that required for well-formed documents. When this happens, an attacker may exploit an asymmetric resource consumption attack to take advantage of the greater processing time to cause a Denial of Service (DoS).

**To analyze the likelihood of this attack, analyze the time taken by a regular XML document vs the time taken by a malformed version of that same document.** Then, consider how an attacker could use this vulnerability in conjunction with an XML flood attack using multiple documents to amplify the effect.

### Applications Processing Malformed Data

**Certain XML parsers have the ability to recover malformed documents.** They can be instructed to try their best to return a valid tree with all the content that they can manage to parse, regardless of the document's noncompliance with the specifications. **Since there are no predefined rules for the recovery process, the approach and results from these parsers may not always be the same. Using malformed documents might lead to unexpected issues related to data integrity.**

The following two scenarios illustrate attack vectors a parser will analyze in recovery mode:

#### Malformed Document to Malformed Document

According to the XML specification, the string `--` (double-hyphen) must not occur within comments. Using the recovery mode of lxml and PHP, the following document will remain the same after being recovered:

```xml
<element>
 <!-- one
  <!-- another comment
 comment -->
</element>
```

#### Well-Formed Document to Well-Formed Document Normalized

Certain parsers may consider normalizing the contents of your `CDATA` sections. This means that they will update the special characters contained in the `CDATA` section to contain the safe versions of these characters even though is not required:

```xml
<element>
 <![CDATA[<script>a=1;</script>]]>
</element>
```

Normalization of a `CDATA` section is not a common rule among parsers. Libxml could transform this document to its canonical version, but although well formed, its contents may be considered malformed depending on the situation:

```xml
<element>
 &lt;script&gt;a=1;&lt;/script&gt;
</element>
```

### Handling coercive parsing

**One popular coercive attack in XML involves parsing deeply nested XML documents without their corresponding ending tags. The idea is to make the victim use up -and eventually deplete- the machine's resources and cause a denial of service on the target.** Reports of a DoS attack in Firefox 3.67 included the use of 30,000 open XML elements without their corresponding ending tags. Removing the closing tags simplified the attack since it requires only half of the size of a well-formed document to accomplish the same results. The number of tags being processed eventually caused a stack overflow. A simplified version of such a document would look like this:

```xml
<A1>
 <A2>
  <A3>
   ...
    <A30000>
```

## Violation of XML Specification Rules

Unexpected consequences may result from manipulating documents using parsers that do not follow W3C specifications. **It may be possible to achieve crashes and/or code execution when the software does not properly verify how to handle incorrect XML structures. Feeding the software with fuzzed XML documents may expose this behavior.**

## Dealing with invalid XML documents

**Attackers may introduce unexpected values in documents to take advantage of an application that does not verify whether the document contains a valid set of values.** Treat schema validation as a fail-closed contract: accept a document only after the entire document passes validation; otherwise reject it. More than one schema language can be layered (structural validation first, value restrictions second, for example). Streaming validators can deliver content before reporting a later validation failure, so do not commit application effects until all validation succeeds, and discard buffered results on failure.

Each XML document should be validated against a precisely defined [XML Schema](https://www.w3.org/TR/xmlschema-2/) (not a [DTD](https://www.w3schools.com/xml/xml_dtd_intro.asp)) in which every element and attribute carries explicit restrictions. The principles:

- **Validate against a strict, versioned, local schema.** Compile the schema from files kept with the application (or from a known-good, integrity-checked repository) instead of following the schema location hints embedded in the document. If schema files are retrieved remotely, use secure, encrypted transport. Hint-driven loading fetches attacker-influenced URLs, and the Java Development Kit (JDK) documentation notes that "the use of schema location hints introduces a vulnerability to denial-of-service attacks" ([javax.xml.validation.SchemaFactory](https://docs.oracle.com/javase/8/docs/api/javax/xml/validation/SchemaFactory.html)). Keep the schema under version control, and re-validate whenever either the schema or the documents change.
- **Reject, do not repair.** If validation fails, refuse the entire document. "Mostly valid" documents are exactly the shape used to smuggle a semantics-changing element past review.
- **Restrict every value with the schema's own [facets](https://www.w3.org/TR/xmlschema-2/#facets).** For strings, use `length` for a fixed length, or `minLength` and `maxLength` for a range, together with `pattern` or `enumeration` for allowed values. For numbers and amounts, use decimal types with `minInclusive`/`maxInclusive` and `totalDigits`/`fractionDigits` rather than floating point. Specify explicit units for measures, and explicit formats where a value is consumed by a legacy backend instead of the schema-checked pipeline.
- **Type by meaning, not by length.** Where the receiving system enforces its own type (a database column, a currency type), the schema type should express the same size and range so the two layers cannot disagree about what was stored.
- **Keep documents small and shallow.** Enforce document-size, nesting-depth, and element-count limits when receiving and parsing XML. In the schema, set an appropriate finite `maxOccurs` for repeated elements rather than `maxOccurs="unbounded"`. Follow the [XML External Entity Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html) for DTD and external-entity hardening. Schema validation is a second line of defense, not a replacement for parser hardening and resource limits.

Schema validity is not data authorization: a valid document can still come from an unprivileged user, so value-level authorization (resolving identifiers against server-side state instead of trusting document content, for example) remains the application's job.

The following element definition is the concise example for this section; facets restrict both its size and its vocabulary:

```xml
<xs:element name="country">
 <xs:simpleType>
  <xs:restriction base="xs:string">
   <xs:length value="2"/>
   <xs:pattern value="[A-Z]{2}"/>
  </xs:restriction>
 </xs:simpleType>
</xs:element>
```

### Jumbo Payloads

**Sending an XML document of 1GB requires only a second of server processing and might not be worth consideration as an attack. Instead, an attacker would look for a way to minimize the CPU and traffic used to generate this type of attack, compared to the overall amount of server CPU or traffic used to handle the requests.**

#### Traditional Jumbo Payloads

**There are two primary methods to make a document larger than normal:**

**- Depth attack: using a huge number of elements, element names, and/or element values.**

**- Width attack: using a huge number of attributes, attribute names, and/or attribute values.**

In most cases, the overall result will be a huge document. This is a short example of what this looks like:

```xml
<SOAPENV:ENVELOPE XMLNS:SOAPENV="HTTP://SCHEMAS.XMLSOAP.ORG/SOAP/ENVELOPE/"
                  XMLNS:EXT="HTTP://COM/IBM/WAS/WSSAMPLE/SEI/ECHO/B2B/EXTERNAL">
 <SOAPENV:HEADER LARGENAME1="LARGEVALUE"
                 LARGENAME2="LARGEVALUE2"
                 LARGENAME3="LARGEVALUE3" …>
 ...
```

#### "Small" Jumbo Payloads

**The following example is a very small document, but the results of processing this could be similar to those of processing traditional jumbo payloads.** The purpose of such a small payload is that it allows an attacker to send many documents fast enough to make the application consume most or all of the available resources:

```xml
<?xml version="1.0"?>
<!DOCTYPE root [
 <!ENTITY file SYSTEM "http://attacker/huge.xml" >
]>
<root>&file;</root>
```

### Schema Poisoning

**When an attacker is capable of introducing modifications to a schema, there could be multiple high-risk consequences. In particular, the effect of these consequences will be more dangerous if the schemas are using [DTD](https://www.w3schools.com/xml/xml_dtd_intro.asp) (e.g., file retrieval, denial of service).** An attacker could exploit this type of vulnerability in numerous scenarios, always depending on the location of the schema.

#### Local Schema Poisoning

**Local schema poisoning happens when schemas are available in the same host, whether or not the schemas are embedded in the same XML document.**

##### Embedded Schema

**The most trivial type of schema poisoning takes place when the schema is defined within the same XML document.** Consider the following, unknowingly vulnerable example provided by the W3C :

```xml
<?xml version="1.0"?>
<!DOCTYPE note [
 <!ELEMENT note (to,from,heading,body)>
 <!ELEMENT to (#PCDATA)>
 <!ELEMENT from (#PCDATA)>
 <!ELEMENT heading (#PCDATA)>
 <!ELEMENT body (#PCDATA)>
]>
<note>
 <to>Tove</to>
 <from>Jani</from>
 <heading>Reminder</heading>
 <body>Don't forget me this weekend</body>
</note>
```

All restrictions on the note element could be removed or altered, allowing the sending of any type of data to the server. Furthermore, if the server is processing external entities, the attacker could use the schema, for example, to read remote files from the server. **This type of schema only serves as a suggestion for sending a document, but it must contain a way to check the embedded schema integrity to be used safely. Attacks through embedded schemas are commonly used to exploit external entity expansions. Embedded XML schemas can also assist in port scans of internal hosts or brute force attacks.**

##### Incorrect Permissions

**You can often circumvent the risk of using remotely tampered versions by processing a local schema.**

```xml
<!DOCTYPE note SYSTEM "note.dtd">
<note>
 <to>Tove</to>
 <from>Jani</from>
 <heading>Reminder</heading>
 <body>Don't forget me this weekend</body>
</note>
```

**However, if the local schema does not contain the correct permissions, an internal attacker could alter the original restrictions.** The following line exemplifies a schema using permissions that allow any user to make modifications:

```text
-rw-rw-rw-  1 user  staff  743 Jan 15 12:32 note.dtd
```

The permissions set on `name.dtd` allow any user on the system to make modifications. This vulnerability is clearly not related to the structure of an XML or a schema, but since these documents are commonly stored in the filesystem, it is worth mentioning that an attacker could exploit this type of problem.

#### Remote Schema Poisoning

**Schemas defined by external organizations are normally referenced remotely. If capable of diverting or accessing the network's traffic, an attacker could cause a victim to fetch a distinct type of content rather than the one originally intended.**

##### Man-in-the-Middle (MitM) Attack

When documents reference remote schemas using the unencrypted Hypertext Transfer Protocol (HTTP), the communication is performed in plain text and an attacker could easily tamper with traffic. **When XML documents reference remote schemas using an HTTP connection, the connection could be sniffed and modified before reaching the end user:**

```xml
<!DOCTYPE note SYSTEM "http://example.com/note.dtd">
<note>
 <to>Tove</to>
 <from>Jani</from>
 <heading>Reminder</heading>
 <body>Don't forget me this weekend</body>
</note>
```

The remote file `note.dtd` could be susceptible to tampering when transmitted using the unencrypted HTTP protocol. One tool available to facilitate this type of attack is mitmproxy .

##### DNS-Cache Poisoning

Domain Name System (DNS) cache poisoning can change the IP address returned by a forward hostname lookup and redirect a schema connection. With HTTPS, the client must also [verify the certificate against the requested hostname](https://www.rfc-editor.org/rfc/rfc9110.html#section-4.3.4). DNS redirection alone does not let an attacker substitute schema content when that verification succeeds.

The previous example referenced the host `example.com` using an unencrypted protocol.

When switching to HTTPS, the location of the remote schema is `https://example.com/note.dtd`. Suppose a hostname lookup normally returns the following address:

```bash
$ host example.com
example.com has address 1.1.1.1
```

If an attacker compromises the DNS being used, the previous hostname could now point to a new, different IP controlled by the attacker `2.2.2.2`:

```bash
$ host example.com
example.com has address 2.2.2.2
```

The redirected HTTPS connection must fail if the attacker cannot present a certificate trusted for `example.com`. Content substitution requires an additional failure, such as disabled certificate verification or compromise of the certificate trust chain or legitimate server credentials. Keep certificate and hostname verification enabled and stop schema retrieval on verification failure. HTTPS authenticates the server; it does not make a schema safe if the legitimate host is compromised.

##### Evil Employee Attack

When third parties host and define schemas, the contents are not under the control of the schemas' users. **Any modifications introduced by a malicious employee-or an external attacker in control of these files-could impact all users processing the schemas. Subsequently, attackers could affect the confidentiality, integrity, or availability of other services (especially if the schema in use is [DTD](https://www.w3schools.com/xml/xml_dtd_intro.asp)).**

### XML Entity Expansion

**Processing a [DTD](https://www.w3.org/TR/xml/#dt-entdecl) from untrusted input enables two kinds of attack.** Internal entities alone can exhaust memory and CPU ([CWE-776](https://cwe.mitre.org/data/definitions/776.html)): nested entities that each reference the next layer several times expand exponentially (the "billion laughs" attack), and many references to one large entity expand quadratically. These attacks need no external entity or network access, so blocking external entities does not stop them. External entities add local file disclosure ([CWE-611](https://cwe.mitre.org/data/definitions/611.html)) and requests to internal network resources ([SSRF](https://cwe.mitre.org/data/definitions/918.html)). One small document is enough to read a local file:

```xml
<!DOCTYPE contact [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<contact>&xxe;</contact>
```

When the resolved entity is not reflected in the response or in an error message, the attacker can still confirm the attack or retrieve content out of band through [parameter entities and a remote DTD](https://portswigger.net/web-security/xxe/blind). An external DTD reference in the `DOCTYPE` makes the parser fetch a URL even without any entity declaration (see [Remote Schema Poisoning](#remote-schema-poisoning)).

Disable DTD processing for untrusted XML; this blocks all of the attacks above. If a DTD is genuinely required, disable external entities and external DTD loading, and enforce entity expansion and entity size limits (for Java, see the processing limits in the [JAXP Security Guide](https://docs.oracle.com/en/java/javase/25/security/java-api-xml-processing-jaxp-security-guide.html)). Parser-specific settings are in the [XML External Entity Prevention Cheat Sheet](XML_External_Entity_Prevention_Cheat_Sheet.md).

## References

- [W3C: Extensible Markup Language (XML) 1.0](https://www.w3.org/TR/xml/)
- [W3C: XML Schema Definition Language (XSD) 1.1, Part 2 — Datatypes](https://www.w3.org/TR/xmlschema11-2/)
- [Oracle Java 25: JAXP Security Guide](https://docs.oracle.com/en/java/javase/25/security/java-api-xml-processing-jaxp-security-guide.html)
