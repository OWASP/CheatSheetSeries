# Security Definitions Cheat Sheet

## Encoding vs Escaping

**Baseline Definition:**  
- **Encoding**: Transforming data into another format using a publicly available scheme (e.g., Base64, URL encoding).  
- **Escaping**: Adding special characters to data so that it is treated as plain text, not as executable code (e.g., HTML entity escaping).  
- Sources: [OWASP](https://owasp.org), [CNCF Glossary](https://glossary.cncf.io)

**Why it Matters in Security:**  
- Misunderstanding these terms can cause developers to use the wrong defense mechanism.  
- Encoding does **not** protect against injection attacks, while escaping is often critical for preventing XSS.  

**Real-World Example:**  
- Developer Base64-encodes untrusted input and assumes it is “safe,” but the input is still executable after decoding → leading to SQL injection or XSS.  
- Proper HTML escaping (`&lt;script&gt;`) prevents execution in the browser.  

**Best Practices:**  
- Use escaping when injecting untrusted data into a language/markup (HTML, SQL, XML).  
- Use encoding only for safely transmitting data (e.g., sending binary over text).  
- Do **not** confuse encoding with security controls.  

**Snippet Example (XSS Prevention):**
```html
<!-- Unsafe -->
<div>Welcome, <%= userInput %></div>

<!-- Safe (escaped) -->
<div>Welcome, <%= HtmlUtils.htmlEscape(userInput) %></div>
