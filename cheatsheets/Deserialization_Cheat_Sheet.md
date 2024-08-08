# Deserialization Cheat Sheet

## Introduction

This article is focused on providing clear, actionable guidance for safely deserializing untrusted data in your applications.

## What is Deserialization

**Serialization** is the process of turning some object into a data format that can be restored later. People often serialize objects in order to save them for storage, or to send as part of communications.

**Deserialization** is the reverse of that process, taking data structured in some format, and rebuilding it into an object. Today, the most popular data format for serializing data is JSON. Before that, it was XML.

However, many programming languages have native ways to serialize objects. These native formats usually offer more features than JSON or XML, including customization of the serialization process.

Unfortunately, the features of these native deserialization mechanisms can sometimes be repurposed for malicious effect when operating on untrusted data. Attacks against deserializers have been found to allow denial-of-service, access control, or remote code execution (RCE) attacks.

## Guidance on Deserializing Objects Safely

The following language-specific guidance attempts to enumerate safe methodologies for deserializing data that can't be trusted.

### PHP

#### Clear-box Review

Check the use of [`unserialize()`](https://www.php.net/manual/en/function.unserialize.php) function and review how the external parameters are accepted. Use a safe, standard data interchange format such as JSON (via `json_decode()` and `json_encode()`) if you need to pass serialized data to the user.

### Python

#### Opaque-box Review

If the traffic data contains the symbol dot `.` at the end, it's very likely that the data was sent in serialization. It will be only true if the data is not being encoded using Base64 or Hexadecimal schemas. If the data is being encoded, then it's best to check if the serialization is likely happening or not by looking at the starting characters of the parameter value. For example if data is Base64 encoded, then it will most likely start with `gASV`.

#### Clear-box Review

The following API in Python will be vulnerable to serialization attack. Search code for the pattern below.

1. The uses of `pickle/c_pickle/_pickle` with `load/loads`:

```python
import pickle
data = """ cos.system(S'dir')tR. """
pickle.loads(data)
```

2. Uses of `PyYAML` with `load`:

```python
import yaml
document = "!!python/object/apply:os.system ['ipconfig']"
print(yaml.load(document))
```

3. Uses of `jsonpickle` with `encode` or `store` methods.

### Java

The following techniques are all good for preventing attacks against deserialization against [Java's Serializable format](https://docs.oracle.com/javase/7/docs/api/java/io/Serializable.html).

Implementation advices:

- In your code, override the `ObjectInputStream#resolveClass()` method to prevent arbitrary classes from being deserialized. This safe behavior can be wrapped in a library like [SerialKiller](https://github.com/ikkisoft/SerialKiller).
- Use a safe replacement for the generic `readObject()` method as seen here. Note that this addresses "[billion laughs](https://en.wikipedia.org/wiki/Billion_laughs_attack)" type attacks by checking input length and number of objects deserialized.

#### Clear-box Review

Be aware of the following Java API uses for potential serialization vulnerability.

1. `XMLdecoder` with external user defined parameters

2. `XStream` with `fromXML` method (xstream version <= v1.4.6 is vulnerable to the serialization issue)

3. `ObjectInputStream` with `readObject`

4. Uses of `readObject`, `readObjectNoData`, `readResolve` or `readExternal`

5. `ObjectInputStream.readUnshared`

6. `Serializable`

#### Opaque-box Review

If the captured traffic data includes the following patterns, it may suggest that the data was sent in Java serialization streams:

- `AC ED 00 05` in Hex
- `rO0` in Base64
- `Content-type` header of an HTTP response set to `application/x-java-serialized-object`

#### Prevent Data Leakage and Trusted Field Clobbering

If there are data members of an object that should never be controlled by end users during deserialization or exposed to users during serialization, they should be declared as [the `transient` keyword](https://docs.oracle.com/javase/7/docs/platform/serialization/spec/serial-arch.html#7231) (section *Protecting Sensitive Information*).

For a class that defined as Serializable, the sensitive information variable should be declared as `private transient`.

For example, the class `myAccount`, the variables 'profit' and 'margin' were declared as transient to prevent them from being serialized.

```java
public class myAccount implements Serializable
{
    private transient double profit; // declared transient

    private transient double margin; // declared transient
    ....
```

#### Prevent Deserialization of Domain Objects

Some of your application objects may be forced to implement `Serializable` due to their hierarchy. To guarantee that your application objects can't be deserialized, a `readObject()` method should be declared (with a `final` modifier) which always throws an exception:

```java
private final void readObject(ObjectInputStream in) throws java.io.IOException {
    throw new java.io.IOException("Cannot be deserialized");
}
```

#### Harden Your Own java.io.ObjectInputStream

The `java.io.ObjectInputStream` class is used to deserialize objects. It's possible to harden its behavior by subclassing it. This is the best solution if:

- you can change the code that does the deserialization;
- you know what classes you expect to deserialize.

The general idea is to override [`ObjectInputStream.html#resolveClass()`](http://docs.oracle.com/javase/7/docs/api/java/io/ObjectInputStream.html#resolveClass(java.io.ObjectStreamClass)) in order to restrict which classes are allowed to be deserialized.

Because this call happens before a `readObject()` is called, you can be sure that no deserialization activity will occur unless the type is one that you allow.

A simple example is shown here, where the `LookAheadObjectInputStream` class is guaranteed to **not** deserialize any other type besides the `Bicycle` class:

```java
public class LookAheadObjectInputStream extends ObjectInputStream {

    public LookAheadObjectInputStream(InputStream inputStream) throws IOException {
        super(inputStream);
    }

    /**
    * Only deserialize instances of our expected Bicycle class
    */
    @Override
    protected Class<?> resolveClass(ObjectStreamClass desc) throws IOException, ClassNotFoundException {
        if (!desc.getName().equals(Bicycle.class.getName())) {
            throw new InvalidClassException("Unauthorized deserialization attempt", desc.getName());
        }
        return super.resolveClass(desc);
    }
}
```

More complete implementations of this approach have been proposed by various community members:

- [NibbleSec](https://github.com/ikkisoft/SerialKiller) - a library that allows creating lists of classes that are allowed to be deserialized
- [IBM](https://www.ibm.com/developerworks/library/se-lookahead/) - the seminal protection, written years before the most devastating exploitation scenarios were envisioned.
- [Apache Commons IO classes](https://commons.apache.org/proper/commons-io/javadocs/api-2.5/org/apache/commons/io/serialization/ValidatingObjectInputStream.html)

#### Harden All java.io.ObjectInputStream Usage with an Agent

As mentioned above, the `java.io.ObjectInputStream` class is used to deserialize objects. It's possible to harden its behavior by subclassing it. However, if you don't own the code or can't wait for a patch, using an agent to weave in hardening to `java.io.ObjectInputStream` is the best solution.

Globally changing `ObjectInputStream` is only safe for block-listing known malicious types, because it's not possible to know for all applications what the expected classes to be deserialized are. Fortunately, there are very few classes needed in the denylist to be safe from all the known attack vectors, today.

It's inevitable that more "gadget" classes will be discovered that can be abused. However, there is an incredible amount of vulnerable software exposed today, in need of a fix. In some cases, "fixing" the vulnerability may involve re-architecting messaging systems and breaking backwards compatibility as developers move towards not accepting serialized objects.

To enable these agents, simply add a new JVM parameter:

```text
-javaagent:name-of-agent.jar
```

Agents taking this approach have been released by various community members:

- [rO0 by Contrast Security](https://github.com/Contrast-Security-OSS/contrast-rO0)

A similar, but less scalable approach would be to manually patch and bootstrap your JVM's ObjectInputStream. Guidance on this approach is available [here](https://github.com/wsargent/paranoid-java-serialization).

#### Other Deserialization Libraries and Formats

While the advice above is focused on [Java's Serializable format](https://docs.oracle.com/javase/7/docs/api/java/io/Serializable.html), there are a number of other libraries
that use other formats for deserialization. Many of these libraries may have similar security
issues if not configured correctly. This section lists some of these libraries and
recommended configuration options to avoid security issues when deserializing untrusted data:

**Can be used safely with default configuration:**

The following libraries can be used safely with default configuration:

- **[fastjson2](https://github.com/alibaba/fastjson2)** (JSON) - can be used safely as long as
the [**autotype**](https://github.com/alibaba/fastjson2/wiki/fastjson2_autotype_cn) option is not turned on
- **[jackson-databind](https://github.com/FasterXML/jackson-databind)** (JSON) - can be used safely as long
as polymorphism is not used ([see blog post](https://cowtowncoder.medium.com/on-jackson-cves-dont-panic-here-is-what-you-need-to-know-54cd0d6e8062))
- **[Kryo v5.0.0+](https://github.com/EsotericSoftware/kryo)** (custom format) - can be used safely
as long as class registration is not turned **off** ([see documentation](https://github.com/EsotericSoftware/kryo#optional-registration)
and [this issue](https://github.com/EsotericSoftware/kryo/issues/929))
- **[YamlBeans v1.16+](https://github.com/EsotericSoftware/yamlbeans)** (YAML) - can be used safely
as long as the **UnsafeYamlConfig** class isn't used (see [this commit](https://github.com/EsotericSoftware/yamlbeans/commit/b1122588e7610ae4e0d516c50d08c94ee87946e6))
    - _NOTE: because these versions are not available in Maven Central,
[a fork exists](https://github.com/Contrast-Security-OSS/yamlbeans) that can be used instead._
- **[XStream v1.4.17+](https://x-stream.github.io/)** (JSON and XML) - can be used safely
as long as the allowlist and other security controls are not relaxed ([see documentation](https://x-stream.github.io/security.html))

**Requires configuration before can be used safely:**

The following libraries require configuration options to be set before they can be used safely:

- **[fastjson v1.2.68+](https://github.com/alibaba/fastjson)** (JSON) - cannot be used safely unless
the [**safemode**](https://github.com/alibaba/fastjson/wiki/fastjson_safemode_en) option is turned on, which disables
deserialization of any class ([see documentation](https://github.com/alibaba/fastjson/wiki/enable_autotype)).
Previous versions are not safe.
- **[json-io](https://github.com/jdereg/json-io)** (JSON) - cannot be used safely since the use of **@type** property in
JSON allows deserialization of any class. Can only be used safely in following situations:
    - In [non-typed mode](https://github.com/jdereg/json-io/blob/master/user-guide.md#non-typed-usage) using the **JsonReader.USE_MAPS** setting which turns off generic object deserialization
    - [With a custom deserializer](https://github.com/jdereg/json-io/blob/master/user-guide.md#customization-technique-4-custom-serializer) controlling which classes get deserialized
- **[Kryo < v5.0.0](https://github.com/EsotericSoftware/kryo)** (custom format) - cannot be used safely unless class registration is turned **on**,
which disables deserialization of any class ([see documentation](https://github.com/EsotericSoftware/kryo#optional-registration)
and [this issue](https://github.com/EsotericSoftware/kryo/issues/929))
    - _NOTE: other wrappers exist around Kryo such as [Chill](https://github.com/twitter/chill), which may also have class registration
not required by default regardless of the underlying version of Kryo being used_
- **[SnakeYAML](https://bitbucket.org/snakeyaml/snakeyaml/src)** (YAML) - cannot be used safely unless
the **org.yaml.snakeyaml.constructor.SafeConstructor** class is used, which disables
deserialization of any class ([see docs](https://bitbucket.org/snakeyaml/snakeyaml/wiki/CVE-2022-1471))

**Cannot be used safely:**

The following libraries are either no longer maintained or cannot be used safely with untrusted input:

- **[Castor](https://github.com/castor-data-binding/castor)** (XML) - appears to be abandoned with no commits since 2016
- **[fastjson < v1.2.68](https://github.com/alibaba/fastjson)** (JSON) - these versions allows deserialization of any class
([see documentation](https://github.com/alibaba/fastjson/wiki/enable_autotype))
- **[XMLDecoder in the JDK](https://docs.oracle.com/javase/8/docs/api/java/beans/XMLDecoder.html)** (XML) - _"close to impossible to securely deserialize Java objects in this format from untrusted inputs"_
("Red Hat Defensive Coding Guide", [end of section 2.6.5](https://redhat-crypto.gitlab.io/defensive-coding-guide/#sect-Defensive_Coding-Tasks-Serialization-XML))
- **[XStream < v1.4.17](https://x-stream.github.io/)** (JSON and XML) - these versions allows deserialization of any class (see [documentation](https://x-stream.github.io/security.html#explicit))
- **[YamlBeans < v1.16](https://github.com/EsotericSoftware/yamlbeans)** (YAML) - these versions allows deserialization of any class
(see [this document](https://github.com/Contrast-Security-OSS/yamlbeans/blob/main/SECURITY.md))

### .Net CSharp

#### Clear-box Review

Search the source code for the following terms:

1. `TypeNameHandling`
2. `JavaScriptTypeResolver`

Look for any serializers where the type is set by a user controlled variable.

#### Opaque-box Review

Search for the following base64 encoded content that starts with:

```text
AAEAAAD/////
```

Search for content with the following text:

1. `TypeObject`
2. `$type:`

#### General Precautions

Microsoft has stated that the `BinaryFormatter` type is dangerous and cannot be secured. As such, it should not be used. Full details are in the [BinaryFormatter security guide](https://docs.microsoft.com/en-us/dotnet/standard/serialization/binaryformatter-security-guide).

Don't allow the datastream to define the type of object that the stream will be deserialized to. You can prevent this by for example using the `DataContractSerializer` or `XmlSerializer` if at all possible.

Where `JSON.Net` is being used make sure the `TypeNameHandling` is only set to `None`.

```csharp
TypeNameHandling = TypeNameHandling.None
```

If `JavaScriptSerializer` is to be used then do not use it with a `JavaScriptTypeResolver`.

If you must deserialize data streams that define their own type, then restrict the types that are allowed to be deserialized. One should be aware that this is still risky as many native .Net types potentially dangerous in themselves. e.g.

```csharp
System.IO.FileInfo
```

`FileInfo` objects that reference files actually on the server can when deserialized, change the properties of those files e.g. to read-only, creating a potential denial of service attack.

Even if you have limited the types that can be deserialized remember that some types have properties that are risky. `System.ComponentModel.DataAnnotations.ValidationException`, for example has a property `Value` of type `Object`. if this type is the type allowed for deserialization then an attacker can set the `Value` property to any object type they choose.

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

For `JSON.Net` it is possible to create a safer form of allow-list control using a custom `SerializationBinder`.

Try to keep up-to-date on known .Net insecure deserialization gadgets and pay special attention where such types can be created by your deserialization processes. **A deserializer can only instantiate types that it knows about**.

Try to keep any code that might create potential gadgets separate from any code that has internet connectivity. As an example `System.Windows.Data.ObjectDataProvider` used in WPF applications is a known gadget that allows arbitrary method invocation. It would be risky to have this a reference to this assembly in a REST service project that deserializes untrusted data.

#### Known .NET RCE Gadgets

- `System.Configuration.Install.AssemblyInstaller`
- `System.Activities.Presentation.WorkflowDesigner`
- `System.Windows.ResourceDictionary`
- `System.Windows.Data.ObjectDataProvider`
- `System.Windows.Forms.BindingSource`
- `Microsoft.Exchange.Management.SystemManager.WinForms.ExchangeSettingsProvider`
- `System.Data.DataViewManager, System.Xml.XmlDocument/XmlDataDocument`
- `System.Management.Automation.PSObject`

## Language-Agnostic Methods for Deserializing Safely

### Using Alternative Data Formats

A great reduction of risk is achieved by avoiding native (de)serialization formats. By switching to a pure data format like JSON or XML, you lessen the chance of custom deserialization logic being repurposed towards malicious ends.

Many applications rely on a [data-transfer object pattern](https://en.wikipedia.org/wiki/Data_transfer_object) that involves creating a separate domain of objects for the explicit purpose data transfer. Of course, it's still possible that the application will make security mistakes after a pure data object is parsed.

### Only Deserialize Signed Data

If the application knows before deserialization which messages will need to be processed, they could sign them as part of the serialization process. The application could then to choose not to deserialize any message which didn't have an authenticated signature.

## Mitigation Tools/Libraries

- [Java secure deserialization library](https://github.com/ikkisoft/SerialKiller)
- [SWAT - tool for creating allowlists](https://github.com/cschneider4711/SWAT)
- [NotSoSerial](https://github.com/kantega/notsoserial)

## Detection Tools

- [Java deserialization cheat sheet aimed at pen testers](https://github.com/GrrrDog/Java-Deserialization-Cheat-Sheet)
- [A proof-of-concept tool for generating payloads that exploit unsafe Java object deserialization.](https://github.com/frohoff/ysoserial)
- [Java De-serialization toolkits](https://github.com/brianwrf/hackUtils)
- [Java de-serialization tool](https://github.com/frohoff/ysoserial)
- [.Net payload generator](https://github.com/pwntester/ysoserial.net)
- [Burp Suite extension](https://github.com/federicodotta/Java-Deserialization-Scanner/releases)
- [Java secure deserialization library](https://github.com/ikkisoft/SerialKiller)
- [Serianalyzer is a static bytecode analyzer for deserialization](https://github.com/mbechler/serianalyzer)
- [Payload generator](https://github.com/mbechler/marshalsec)
- [Android Java Deserialization Vulnerability Tester](https://github.com/modzero/modjoda)
- Burp Suite Extension
    - [JavaSerialKiller](https://github.com/NetSPI/JavaSerialKiller)
    - [Java Deserialization Scanner](https://github.com/federicodotta/Java-Deserialization-Scanner)
    - [Burp-ysoserial](https://github.com/summitt/burp-ysoserial)
    - [SuperSerial](https://github.com/DirectDefense/SuperSerial)
    - [SuperSerial-Active](https://github.com/DirectDefense/SuperSerial-Active)

## References

- [Java-Deserialization-Cheat-Sheet](https://github.com/GrrrDog/Java-Deserialization-Cheat-Sheet)
- [Deserialization of untrusted data](https://owasp.org/www-community/vulnerabilities/Deserialization_of_untrusted_data)
- [Java Deserialization Attacks - German OWASP Day 2016](../assets/Deserialization_Cheat_Sheet_GOD16Deserialization.pdf)
- [AppSecCali 2015 - Marshalling Pickles](http://www.slideshare.net/frohoff1/appseccali-2015-marshalling-pickles)
- [FoxGlove Security - Vulnerability Announcement](http://foxglovesecurity.com/2015/11/06/what-do-weblogic-websphere-jboss-jenkins-opennms-and-your-application-have-in-common-this-vulnerability/#websphere)
- [Java deserialization cheat sheet aimed at pen testers](https://github.com/GrrrDog/Java-Deserialization-Cheat-Sheet)
- [A proof-of-concept tool for generating payloads that exploit unsafe Java object deserialization.](https://github.com/frohoff/ysoserial)
- [Java De-serialization toolkits](https://github.com/brianwrf/hackUtils)
- [Java de-serialization tool](https://github.com/frohoff/ysoserial)
- [Burp Suite extension](https://github.com/federicodotta/Java-Deserialization-Scanner/releases)
- [Java secure deserialization library](https://github.com/ikkisoft/SerialKiller)
- [Serianalyzer is a static bytecode analyzer for deserialization](https://github.com/mbechler/serianalyzer)
- [Payload generator](https://github.com/mbechler/marshalsec)
- [Android Java Deserialization Vulnerability Tester](https://github.com/modzero/modjoda)
- Burp Suite Extension
    - [JavaSerialKiller](https://github.com/NetSPI/JavaSerialKiller)
    - [Java Deserialization Scanner](https://github.com/federicodotta/Java-Deserialization-Scanner)
    - [Burp-ysoserial](https://github.com/summitt/burp-ysoserial)
    - [SuperSerial](https://github.com/DirectDefense/SuperSerial)
    - [SuperSerial-Active](https://github.com/DirectDefense/SuperSerial-Active)
- .Net
    - [Alvaro Muñoz: .NET Serialization: Detecting and defending vulnerable endpoints](https://www.youtube.com/watch?v=qDoBlLwREYk)
    - [James Forshaw - Black Hat USA 2012 - Are You My Type? Breaking .net Sandboxes Through Serialization](https://www.youtube.com/watch?v=Xfbu-pQ1tIc)
    - [Jonathan Birch BlueHat v17 - Dangerous Contents - Securing .Net Deserialization](https://www.youtube.com/watch?v=oxlD8VWWHE8)
    - [Alvaro Muñoz & Oleksandr Mirosh - Friday the 13th: Attacking JSON - AppSecUSA 2017](https://www.youtube.com/watch?v=NqHsaVhlxAQ)
- Python
    - [Exploiting Insecure Deserialization bugs found in the Wild (Python Pickles)](https://macrosec.tech/index.php/2021/06/29/exploiting-insecuredeserialization-bugs-found-in-the-wild-python-pickles.)
