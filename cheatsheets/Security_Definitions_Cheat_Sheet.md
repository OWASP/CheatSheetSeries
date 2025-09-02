# Security Definitions Cheat Sheet

## Encoding vs Escaping (and Sanitization)

**Baseline Definition:**  

- **Encoding (Output Encoding):** Converting data into a safe representation for a specific output context  
  (e.g., `<` → `&lt;` in HTML). Often referred to as *output encoding* in OWASP materials.  

- **Escaping:** Adding a special character before a control character so it is treated as data, not code  
  (e.g., escaping quotes in SQL or JSON). In practice, escaping and output encoding are sometimes used  
  interchangeably.  

- **Sanitization:** Modifying or stripping unsafe input to enforce a security policy (e.g., removing `<script>` tags).  

**Why it Matters in Security:**  

- Misunderstanding these terms can cause developers to use the wrong defense.  
- **Encoding/escaping** are critical for preventing injection attacks (XSS, SQLi, etc.), but **encoding alone**  
  (like Base64) is not a security control.  
- **Sanitization** can reduce attack surface but is not foolproof—it should complement, not replace,  
  contextual encoding/escaping.  

**Real-World Example:**  

- Developer Base64-encodes untrusted input, assuming it is “safe,” but the value is still dangerous after decoding →  
  possible SQL injection or XSS.  
- Proper HTML output encoding: `&lt;script&gt;alert(1)&lt;/script&gt;` renders harmless text.  
- Sanitization (e.g., stripping `<script>` tags) may preserve content but risks over- or under-filtering.  

**Best Practices:**  

- Always apply **contextual output encoding/escaping** (HTML, JavaScript, CSS, URL, etc.).  
- Use well-tested libraries: [OWASP Java Encoder](https://owasp.org/www-project-java-encoder/),  
  [OWASP ESAPI](https://owasp.org/www-project-esapi/).  
- Use **sanitization** only when you must allow some user HTML  
  (e.g., [OWASP Java HTML Sanitizer](https://owasp.org/www-project-java-html-sanitizer/)).  
- Never confuse **transport encoding** (Base64, URL encoding) with **security encoding**.  

**Snippet Example (XSS Prevention):**

```java
// Unsafe
out.println("Welcome, " + userInput);

// Safe (HTML encoded)
out.println("Welcome, " + Encode.forHtml(userInput));

// Safe (JavaScript encoded)
out.println("var msg = '" + Encode.forJavaScript(userInput) + "';");
