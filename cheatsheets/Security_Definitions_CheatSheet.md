# Security Definitions Cheat Sheet (Draft)

This cheat sheet provides enriched definitions of common security terminology.  
Each entry includes authoritative references, context on why it matters, real-world pitfalls, and best practices.  

---

## Encoding vs Escaping

**Definition (trusted sources):**  
- [OWASP: Data Validation](https://owasp.org/www-community/data_validation)  
- [CNCF Glossary: Encoding](https://glossary.cncf.io/)  

**Why this matters:**  
Developers often mix up encoding and escaping, but they are not the same thing.  
- **Encoding** transforms data into another format (e.g., Base64, UTF-8).  
- **Escaping** ensures data is safe in a specific context (e.g., HTML, SQL, JavaScript).  

Confusing these two can create security issues such as cross-site scripting (XSS) or broken data handling.  

**Common pitfalls:**  
- Assuming that encoding automatically makes data safe. (Base64 input is *not* safe for HTML or SQL).  
- Using the wrong escaping function (HTML escaping inside JavaScript, or SQL escaping instead of parameterized queries).  

**Best practices:**  
- Always apply *context-specific escaping*:  
  - HTML entity escaping for HTML  
  - JavaScript escaping for scripts  
  - URL encoding for query parameters  
  - Parameterized queries for SQL  
- Use trusted libraries or framework functions; avoid writing your own escaping.  

**Example:**  

```html
<!-- ❌ Vulnerable to XSS -->
<div>Welcome, <?php echo $_GET["name"]; ?></div>

<!-- ✅ Safe: HTML escaping applied -->
<div>Welcome, <?php echo htmlspecialchars($_GET["name"], ENT_QUOTES, 'UTF-8'); ?></div>

