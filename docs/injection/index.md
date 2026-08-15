# Injection

Injection flaws share a common root: untrusted data reaches an interpreter that treats it as code or a command rather than literal data. The interpreter can be a SQL engine, a shell, an XML parser, a template engine, or a deserializer. The fix is always the same structural move: separate code from data at the point of construction.

## Topics in this section

| Doc | Core invariant violated |
|---|---|
| [SQL Injection](../01-sql-injection.md) | Query structure is fixed at write time, not runtime |
| [NoSQL Injection](../20-nosql-injection.md) | Operator keys are not user-controlled |
| [OS Command Injection](../05-command-injection.md) | Shell interpolation never touches user input |
| [Path Traversal & LFI](../11-path-traversal-lfi.md) | Resolved path stays within authorized base |
| [XXE Injection](../06-xxe.md) | XML parsers never resolve external entities |
| [SSTI](../07-ssti.md) | Template rendering context is not user-supplied |
| [Insecure Deserialization](../08-insecure-deserialization.md) | Deserialized class is never user-chosen |
| [File Upload](../10-file-upload.md) | Uploaded content is never executed in server context |

## Common escalation chain

Injection → code execution → file read → SSRF → lateral movement. SQL injection reaching `xp_cmdshell` or `INTO OUTFILE` and LFI reaching log poisoning are the canonical paths. Any injection primitive that reaches a system call or a file write is a potential RCE vector.
