# SPIFFE and SPIRE

> Workload identity replaces the bearer-token-in-a-config-file pattern with a cryptographic identity issued to a running process by a trusted local attestor. SPIFFE defines the identity (a URI like `spiffe://prod.example.com/ns/payments/sa/api`) and how it embeds in an X.509 or JWT SVID. SPIRE is the reference control plane: a Server that mints SVIDs and per-node Agents that attest workloads through kernel and orchestrator evidence (uid, cgroup, k8s pod labels, AWS IID). The security of the whole system reduces to one question: does the Agent's workload attestation actually prove the caller is the workload named by the selector, or can a co-tenant forge the evidence. Every real SPIRE incident is either a weak selector (attestation bypass), a leaky Workload API socket, an unverified federation bundle, or an SVID with a lifetime long enough that revocation becomes fiction.

## Quick reference

X.509-SVID: an ordinary X.509 leaf certificate whose only Subject Alternative Name is a `URI` extension holding the SPIFFE ID. No DNS SAN, no CN identity, no email. RFC 5280 URI-SAN semantics are what a verifier checks.

```
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number: 0x7f3a2b...
        Signature Algorithm: ecdsa-with-SHA384
        Issuer: O=SPIFFE, CN=prod.example.com
        Validity
            Not Before: Aug  8 14:00:00 2026 GMT
            Not After : Aug  8 15:00:00 2026 GMT     # 1 hour
        Subject:                                      # empty per SPIFFE X.509 profile
        Subject Public Key Info:
            Public Key Algorithm: id-ecPublicKey
            EC Public Key: (P-384) ...
        X509v3 extensions:
            X509v3 Key Usage: critical
                Digital Signature, Key Encipherment
            X509v3 Extended Key Usage:
                TLS Web Server Authentication, TLS Web Client Authentication
            X509v3 Subject Alternative Name: critical
                URI:spiffe://prod.example.com/ns/payments/sa/api    # THE identity
            X509v3 Basic Constraints: critical
                CA:FALSE
```

Workload API request over the Agent's Unix Domain Socket (SPIFFE Workload API, gRPC):

```
$ SPIFFE_ENDPOINT_SOCKET=unix:///run/spire/agent-sockets/spire-agent.sock \
    grpcurl -plaintext -unix /run/spire/agent-sockets/spire-agent.sock \
    SpiffeWorkloadAPI/FetchX509SVID
# Agent does NOT trust anything the caller says; it stats the socket peer,
# resolves PID, then re-runs selectors: unix:uid, k8s:pod-label, docker:image-id
{
  "svids": [{
    "spiffe_id": "spiffe://prod.example.com/ns/payments/sa/api",
    "x509_svid": "<DER cert chain>",
    "x509_svid_key": "<PKCS8 private key>",
    "bundle": "<trust bundle DER>",
    "hint": ""
  }],
  "crl": [],
  "federated_bundles": {}
}
```

| Invariant | Where enforced | How violated | Source |
| --- | --- | --- | --- |
| SPIFFE ID appears only in a URI SAN, never CN or DNS SAN | X.509-SVID verifier (go-spiffe, java-spiffe) | Verifier that also honors CN or DNS names on SVID certs; issuer that emits DNS SANs | SPIFFE X.509 SVID spec, RFC 5280 |
| Workload attestation runs on Agent, from kernel or orchestrator evidence, never from anything the caller sends | SPIRE Agent workload attestors (unix, k8s, docker) | Selectors bound only to caller-supplied labels or env vars | SPIFFE Workload API spec |
| Agent Workload API socket is reachable only by workloads that share the node's PID namespace | Socket file mode, hostPath mount scope | World-readable socket, socket bind-mounted into every container | SPIFFE Workload API spec |
| Trust bundle for a federated trust domain is fetched over an authenticated channel and pinned | SPIRE Server federation configuration | HTTP fetch, no TLS pin, TOFU on first sync | SPIFFE Federation spec |
| SVID lifetime short enough that revocation is unnecessary (default 1h X.509, 5m JWT) | SPIRE Server default TTL, registration entry TTL | Days-long SVIDs, JWT-SVIDs with `exp` measured in hours | SPIFFE X.509 and JWT SVID specs |
| JWT-SVID audience must be checked; `sub` is the SPIFFE ID | Relying party JWT-SVID validator | Accepting any audience, treating `iss` as identity | SPIFFE JWT SVID spec |
| SPIRE Server signing key material stored in KMS or HSM, not on local disk | SPIRE Server KeyManager plugin | `disk` KeyManager in production, single-node key file | SPIRE Server docs |

## How it works

SPIFFE (Secure Production Identity Framework For Everyone) is three specs plus a naming convention. The convention: identities are URIs of the form `spiffe://<trust-domain>/<path>`. The trust domain is a security boundary owned by one issuer; the path is what the issuer chooses to expose as workload identity, typically Kubernetes namespace and ServiceAccount, or a role name. The specs are the X.509-SVID profile, the JWT-SVID profile, and the Workload API (a gRPC service the workload calls to fetch its SVID). SPIRE (SPIFFE Runtime Environment) is the reference implementation of a control plane that produces SVIDs conforming to these specs.<sup>[[1]](#ref1)</sup><sup>[[2]](#ref2)</sup><sup>[[3]](#ref3)</sup>

### Trust domain, SPIFFE ID, SVID

A trust domain is a namespace of identities under one root CA. `prod.example.com` and `staging.example.com` are separate trust domains with separate roots. Within a trust domain the path is deliberately unstructured in the spec, but real deployments encode k8s coordinates: `spiffe://prod.example.com/ns/payments/sa/api` means Kubernetes namespace `payments`, ServiceAccount `api`. An X.509-SVID is an ordinary X.509 leaf that puts this URI in a URI-type Subject Alternative Name and leaves the Subject empty. The X.509-SVID profile forbids other SANs on leaf SVIDs and requires the URI SAN be critical when the certificate has no other subject material. A JWT-SVID is a signed JWT whose `sub` is the SPIFFE ID, whose `iss` is anything the issuer chooses, and whose `aud` is a named audience that the relying party must check.<sup>[[2]](#ref2)</sup><sup>[[4]](#ref4)</sup>

### SPIRE Server and SPIRE Agent

SPIRE ships as two binaries. Server holds the trust domain's signing keys (ideally in KMS), a datastore of registration entries (rules of the form "if a workload matches these selectors on this node, issue this SPIFFE ID"), and a bundle of trusted CAs. Agent runs one instance per node, mutually authenticates to Server using a node attestation method (aws-iid, gcp-iit, azure-msi, k8s-psat, tpm, join token, sigstore image signature), and receives its own X.509 SVID plus a cached slice of registration entries it might need to satisfy. Workloads on that node connect to the Agent's Workload API over a Unix Domain Socket. The Agent never trusts anything the caller sends over that socket for identity; it derives selectors from kernel and orchestrator sources (`unix:uid`, `unix:pid`, cgroup path, k8s pod labels via kubelet, docker image digest via containerd), matches them against registration entries, and returns the SVID.<sup>[[5]](#ref5)</sup><sup>[[6]](#ref6)</sup>

### Issuance sequence

```mermaid
sequenceDiagram
    autonumber
    participant W as Workload (pod)
    participant A as SPIRE Agent (node)
    participant K as Kubelet / cgroup / /proc
    participant S as SPIRE Server
    participant K2 as KMS / HSM

    Note over A,S: Node bootstrap (once per node)
    A->>S: NodeAttest (aws-iid signed doc, k8s-psat token)
    S->>S: verify attestation evidence, look up node selectors
    S-->>A: Agent X.509 SVID + trust bundle + preloaded entries

    Note over W,A: Workload issuance (every rotation)
    W->>A: FetchX509SVID over UDS (peer PID visible via SO_PEERCRED)
    A->>K: read /proc/<pid>/cgroup, uid, pod labels via kubelet
    A->>A: run workload attestors -> selector set
    A->>A: match selectors against registration entries
    alt no matching entry
        A-->>W: empty response (no SVID)
    else match
        A->>S: sign CSR for spiffe://td/path
        S->>K2: sign with intermediate CA key
        K2-->>S: signature
        S-->>A: X.509 SVID (1h)
        A-->>W: SVID + private key + trust bundle
    end

    Note over W: Workload reconnects before expiry; Agent streams new SVIDs
    Note over W,A: Attack surface: <br/>1) UDS reachable by co-tenant? <br/>2) Selectors forgeable? <br/>3) Bundle federation authenticated?
```

### Federation

Two trust domains that want to accept each other's SVIDs exchange TrustDomainBundles. Federation is not transitive and not automatic. The SPIFFE Federation spec defines a JSON document (the SPIFFE Trust Domain Bundle) that carries the peer trust domain's root keys plus refresh hints, served over HTTPS at a well-known endpoint, and the fetching side must authenticate that endpoint (Web PKI or a pinned certificate). A SPIRE Server configured for federation periodically re-fetches the peer bundle and rotates its cached copy. Workloads that need to speak to a federated identity request `FederatedBundles` alongside their SVID; go-spiffe's `tlsconfig.MTLSClientConfig` will build a verifier that accepts SPIFFE IDs from a specified set of trust domains.<sup>[[7]](#ref7)</sup>

### mTLS with SPIFFE

The most common use is service-to-service mTLS. Both peers present X.509-SVIDs. Verification is not standard Web PKI hostname matching; it is: chain up to the trust domain's root, then check the URI SAN's SPIFFE ID against an authorization policy (`spiffe://prod.example.com/ns/payments/sa/*`). go-spiffe's `tlsconfig` package inverts the normal `crypto/tls` verify to enforce this. See [69-mtls.md](./69-mtls.md) for the general mTLS invariants that still apply on top: session resumption cache safety, downgrade to unauthenticated TLS via SNI routing, revocation without OCSP.

## Attack techniques

### 1. Workload attestation bypass via forgeable selector

The attack lives at the moment the Agent decides "the process on the other end of this Unix socket is workload X." If the Agent's registration entries match on selectors the caller can control, a co-tenant on the same node can register a workload that satisfies the same rule and receives the target SVID. The canonical mistake is a registration entry keyed only on `k8s:pod-label:app=payments-api` where any tenant with pod-create rights in the cluster can add that label. A milder variant: `unix:uid:1000` on a node where multiple workloads share uid 1000 because container images all set USER 1000.

Exploitation is direct: create a pod (or on a VM, a process) that matches the target selectors, mount the Agent's UDS, call FetchX509SVID, receive a valid SVID for the target SPIFFE ID. Nothing about the SVID looks anomalous downstream; the private key is genuine and the chain validates. Confirmation from outside the cluster is a black-box test where the attacker's pod produces an mTLS handshake against the victim service and is admitted.

Escalation is complete impersonation: any policy that trusts `spiffe://td/ns/payments/sa/api` now trusts the attacker. Since SPIRE issues real key material rather than a shared secret, there is no rotation event that revokes the attacker's copy; they can keep rotating until their pod is deleted. The fix is layered selectors that at least one attestor cannot forge from the container itself: SPIRE's `k8s:sa` and `k8s:ns` come from the projected ServiceAccount token verified by the API server, `docker:image-id` from the container runtime's content-addressed digest, `sigstore:*` from a Fulcio-signed image manifest. Never bind identity solely to pod labels or annotations.<sup>[[6]](#ref6)</sup><sup>[[8]](#ref8)</sup>

### 2. Workload API socket exposed to unauthorized workloads

The Agent's UDS is the identity boundary on a node. Anything that can `connect(2)` to it will be attested by the Agent and receive whatever SVID matches its selectors. The socket is typically at `/run/spire/agent-sockets/spire-agent.sock` and is bind-mounted into workload pods via a hostPath or a CSI driver (spire-csi-driver mounts the socket per-pod so it inherits the pod's mount namespace).

Two failure modes. First, an Agent DaemonSet that mounts the socket into every pod via a shared hostPath volume: any container in any pod can `curl-unix-socket` it, and the Agent will attest the container. If the cluster contains a low-trust workload that happens to satisfy some registration entry, it gets an SVID. Second, socket file permissions set world-readable and world-writable so that non-root processes in an otherwise-privileged pod (a sidecar, a debug shell) can talk to it. Confirmation is a one-liner from a shell inside a suspicious pod: `grpcurl -plaintext -unix /var/run/spire/agent.sock SpiffeWorkloadAPI/FetchX509SVID` and observe whether a chain comes back.

Escalation depends on what registration entries exist on the node. In a well-partitioned cluster this returns nothing (empty response). In a cluster where an operator wrote broad entries ("all pods in namespace X get SPIFFE ID Y"), it returns a usable SVID for the shared identity. The real fix is spire-csi-driver mode (per-pod socket, mount tied to the pod's ServiceAccount) plus registration entries scoped to `k8s:sa` (ServiceAccount token verification is not something a sidecar can forge). Do not rely on filesystem permissions on a shared hostPath mount.<sup>[[9]](#ref9)</sup>

### 3. TrustDomainBundle federation with no endpoint authentication

Federation is where two trust domains agree to accept each other's SVIDs. The SPIFFE Federation spec is explicit that the bundle endpoint must be authenticated by the fetching side and the bundle contents integrity-checked. Real deployments miss this in two ways. First, the bundle endpoint is served over plain HTTP inside a "trusted" cluster network, where "trusted" turns out to mean any pod with egress. Second, the endpoint is HTTPS but the fetching Server uses `web` profile (Web PKI) rather than `https_spiffe` profile (self-authenticated using a previously-known SPIFFE ID for the endpoint) and accepts any cert issued by any public CA for the endpoint's hostname.

Attack: attacker who can DNS-poison or BGP-hijack the bundle endpoint hostname, or who has any Web PKI cert for it (mis-issued by a compromised or coerced CA), serves a substituted bundle whose keys they control. On the next refresh (SPIRE default: minutes), the fetching Server rotates in the attacker's keys. Every service in the fetching trust domain now trusts SVIDs signed by the attacker, i.e., any identity in the peer trust domain. Confirmation blind and offline: dump the fetching Server's cached bundle and diff its keys against the peer's known bundle; a divergence at a rotation boundary is the tell.

Escalation is cross-trust-domain impersonation for the duration of the poisoned bundle, which is until an operator notices and pushes a manual bundle. Fix is `https_spiffe` profile with an initial bundle bootstrap out-of-band (kubectl apply of the peer's bundle at federation setup, or fetch over a private mTLS channel to the peer Server), and monitoring on bundle rotation events for unexpected key changes.<sup>[[7]](#ref7)</sup>

### 4. SPIRE Server compromise: the whole trust domain

The Server owns the trust domain root key material. If the Server process (or the datastore it depends on, typically Postgres or MySQL) is popped, the attacker signs arbitrary SVIDs for arbitrary paths under the trust domain and every workload accepts them. Common paths in: SSRF from a co-located admin UI, upgrade of the Server binary from an unverified source, exposure of the Server's healthcheck or admin API without auth, dependency vulnerability in a plugin.

Exploitation once the attacker has code execution on the Server: they read the KeyManager plugin's cached key (if `disk` KeyManager, the file itself; if `aws_kms` or `gcp_kms`, they call the sign API from the Server's IAM role and it works because the Server is authorized to sign). They mint a new registration entry pointing an attacker-controlled SPIFFE ID at a workload they own, wait one Agent poll interval, and receive an SVID for `spiffe://td/admin/root` or whatever the highest-privileged identity in the mesh is. Confirmation externally is limited: SVID issuance shows up in Server logs as a normal event, and unless registration entry changes are tracked in an external audit stream, the new entry looks legitimate.

Escalation is full trust domain compromise: any consumer that trusts the domain trusts the attacker. Recovery requires distributing a new trust bundle (new root key) to every workload out-of-band, since the old bundle is presumed poisoned. Defenses: KMS/HSM KeyManager so keys never live on disk, admin API bound to loopback or accessed only via a bastion, registration-entry writes gated by a separate GitOps flow with human review, audit stream of entries pushed to append-only storage. Long-lived Agents with cached bundles buy some recovery time; short trust bundle refresh intervals shorten the exposure window.<sup>[[5]](#ref5)</sup><sup>[[10]](#ref10)</sup>

### 5. Long SVID lifetimes make rotation and revocation fiction

SPIFFE's design assumption is short SVIDs (X.509 defaults 1h, JWT defaults 5m) with continuous rotation. Operators reach for longer TTLs when they see rotation churn in logs or when a downstream system caches the SVID and fails on rotation. A registration entry with `ttl: 604800` (7 days) is a common misconfiguration.

Attack piggybacks on any of the earlier vectors: attestation bypass, socket exposure, or bundle poisoning. Once the attacker has an SVID, its lifetime is the eviction window. With a 7-day SVID the attacker keeps impersonating for a week regardless of what happens to their pod, whether the registration entry is deleted, or whether the Agent that issued it is restarted; the SVID is a bearer credential once minted. Confirmation is a review of Server registration entries and Agent-issued SVIDs (`spire-server entry show`) filtered on TTL.

Escalation is persistence: an attacker who briefly satisfies a selector obtains a long-lived credential and no longer needs the vulnerability. Fix is enforcing a maximum TTL at Server config (`default_x509_svid_ttl`, `default_jwt_svid_ttl`) below the operational tolerance, and treating any registration entry with a long TTL as a policy violation caught in the GitOps CI. There is no CRL for SVIDs by design: revocation is expiry.<sup>[[2]](#ref2)</sup><sup>[[11]](#ref11)</sup>

### 6. JWT-SVID audience confusion

JWT-SVIDs travel as bearer tokens where mTLS is impractical (browser flows, legacy HTTP intermediaries). The SPIFFE JWT-SVID profile requires the audience claim; each relying party is expected to be a distinct audience string. Real code often skips the audience check and only verifies the signature and `sub`.

Exploitation: any workload that can call `FetchJWTSVID(audience="A")` on the Workload API has a token that services misconfigured to skip audience checks will accept as identity, even if that workload is not authorized to talk to those services. On a large mesh, one over-permissive workload becomes a universal client. Confirmation: obtain a JWT-SVID with audience `foo` and present it to a service that expects audience `bar`; if it validates, the check is missing.

Escalation depends on which services skip the check. If the service that skips is high-value (a config or secrets service), full compromise of that service's authorization decisions. Fix in the go-spiffe validator (`jwtsvid.ParseAndValidate`) is passing the expected audience; do not accept the empty string as a wildcard. In relying party code, prefer libraries that fail closed when audience is unset.<sup>[[4]](#ref4)</sup>

## Defense

### Real fix

1. **Selectors must include at least one attestor the workload cannot forge from inside the container.** The invariant: workload attestation evidence is derived from the kernel or orchestrator, not from process arguments or labels the workload can set. Why it works: SPIRE runs `k8s:sa` and `k8s:ns` attestors that verify the projected ServiceAccount token via the Kubernetes API server, which cross-checks the pod's node against the Agent's node identity; a co-tenant on a different node cannot forge this, and a co-tenant on the same node cannot forge someone else's ServiceAccount. Common wrong implementation: registration entries using only `k8s:pod-label:*` or `unix:user:*` because those were the first selectors shown in a tutorial. Source is the SPIRE workload attestation documentation and the k8s Workload Attestor plugin.<sup>[[6]](#ref6)</sup><sup>[[8]](#ref8)</sup>

2. **Deliver the Workload API socket through spire-csi-driver, one socket per pod, mounted with the pod's ServiceAccount context.** The invariant: only the pod the socket was mounted for can reach it, and the Agent uses `SO_PEERCRED` plus the CSI mount metadata to bind the connecting PID to the pod. Why it works: a shared hostPath mount exposes the Agent's socket to every pod on the node; the CSI driver creates a per-pod socket bind-mount that is invisible to other pods' mount namespaces. Common wrong implementation: `hostPath` volume mounted `readOnly: false` to every pod in a DaemonSet spec that predates the CSI driver. Source is the spire-csi-driver project and the SPIRE deployment guides.<sup>[[9]](#ref9)</sup>

3. **Federate trust bundles via `https_spiffe` profile or out-of-band bootstrap; never TOFU.** The invariant: the SPIRE Server that consumes a peer bundle authenticates the endpoint using either a pre-shared bundle (out-of-band) or the SPIFFE ID of the endpoint itself, not Web PKI, not IP-based ACLs. Why it works: `https_spiffe` inverts the trust chain so the fetcher already knows a SPIFFE ID for the peer endpoint from prior federation; a hijacker cannot present that identity without the peer's private key. Common wrong implementation: `web` profile against a hostname protected only by Let's Encrypt with DNS-01, which any BGP or DNS attacker can force. Source is the SPIFFE Federation spec.<sup>[[7]](#ref7)</sup>

4. **Store SPIRE Server signing keys in KMS/HSM, not on disk.** The invariant: the trust domain root private key is never at rest on a filesystem that a Server compromise could exfiltrate; signing is an RPC to KMS gated by an IAM role scoped to the Server. Why it works: KMS/HSM key material is unexportable, and a Server-side attacker is limited to what they can sign during the compromise window, not to permanent key possession. Common wrong implementation: `KeyManager "disk"` in production `server.conf`. Source is the SPIRE Server KeyManager plugin documentation.<sup>[[5]](#ref5)</sup>

5. **Cap SVID TTL at Server, both X.509 and JWT.** The invariant: the maximum credential lifetime is the maximum time-to-eviction after a compromise, and no operator can lengthen it per-entry beyond a policy ceiling. Why it works: SVIDs have no CRL; expiry is the only revocation mechanism, so a short TTL is a hard upper bound on impersonation duration. Common wrong implementation: raising TTL to a day or a week to reduce log volume, without adjusting the underlying rotation library that misreports errors. Source is the SPIFFE SVID specs and SPIRE server config reference.<sup>[[2]](#ref2)</sup><sup>[[4]](#ref4)</sup>

### Defense in depth

1. **Enforce audience on every JWT-SVID relying party; fail closed on empty audience.** Belt for services that consume JWT-SVIDs alongside X.509 mTLS. `jwtsvid.ParseAndValidate(token, trustDomain, expectedAudience...)` in go-spiffe is the correct entry point.<sup>[[4]](#ref4)</sup>

2. **Node attestation should use a hardware-rooted method where possible.** On AWS, `aws_iid` uses the EC2 instance identity document; on nodes with TPM, `tpm_devid` uses a TPM-resident key. Weaker methods (`join_token`) survive but should be rotated aggressively.<sup>[[5]](#ref5)</sup>

3. **Audit registration entries as code.** Store the desired-state registration entries in a Git repo, apply via `spire-controller-manager` or a CI pipeline, alert on any entry created out-of-band. Prevents an attacker with Server access from silently adding an entry that maps their pod to a privileged identity.<sup>[[10]](#ref10)</sup>

4. **Monitor trust bundle contents at consumers, not just the Server.** Every Agent caches the bundle; ship its hash into observability and alert on unexpected changes. Catches a poisoned federation bundle or a compromised Server that rotates a key without an operator-driven ceremony.<sup>[[7]](#ref7)</sup>

5. **Combine SPIFFE identity with an OPA or admission-webhook authorization layer for high-value calls.** SPIFFE tells you who the caller is; SPIFFE alone does not tell you whether that caller is allowed to invoke this method with these arguments. Complement with policy that consumes the SPIFFE ID as input.<sup>[[8]](#ref8)</sup>

## Detection and telemetry

Instrument the SPIRE Server's event stream. Every SVID issuance is a log line with `spiffe_id`, `selectors`, `agent_id`, `ttl`, and `serial_number`. Ship these to append-only storage and alert on: (a) issuance to a SPIFFE ID from an unexpected Agent node, (b) registration entry create or update outside GitOps hours, (c) SVID TTL greater than policy ceiling, (d) node attestation from a node ID that does not match any known VM inventory.

At the workload side, log the peer SPIFFE ID on every accepted mTLS handshake. Baseline the set of (caller SPIFFE ID, callee SPIFFE ID) pairs over a week; alert on new pairs. Also log the trust bundle serial the peer chained to, so a bundle rotation shows up as a distinct event rather than blending into successful handshakes.

Trust bundle refresh: log every refresh with the incoming bundle's key ID set. Alert when the key set changes outside a scheduled rotation window; alert when a federated bundle refresh produces a key ID that was not present in any prior refresh from that peer within a lookback (this catches a bundle substitution attack even if the peer's own rotation happens on a schedule).

Canary: register a SPIFFE ID that no real workload should hold (`spiffe://td/canary/impossible`) and observe whether anyone ever issues or presents it. Combined with a decoy service that logs its callers, this catches an attacker who found a way to mint SVIDs even if the specific target identity is inconspicuous.

## Interviewer probes

**Q: What exactly is verified when a service accepts an X.509-SVID? Walk me through the chain from bytes to authorization decision.**

Mid: The receiver verifies the chain up to the trust domain root, then extracts the URI SAN and checks the SPIFFE ID against an allowlist.

Principal: The receiver's TLS stack uses a customized verifier (in go-spiffe, `tlsconfig.MTLSServerConfig` swaps the default `crypto/tls` verifier). Verification order: chain up to the pinned trust bundle for the expected trust domain (not Web PKI, not the system trust store), then extract exactly one URI-type SAN and parse it as a SPIFFE ID, then match that ID against the caller's authorization policy. Standard hostname matching is disabled; DNS SANs on an SVID leaf are a spec violation and a verifier that honors them is broken. Bundle rotation is handled by the Workload API streaming updated bundles into the receiver's config, so the verifier's trust anchor set changes without a process restart.

**Q: A team writes a registration entry that reads `k8s:pod-label:app=payments-api`. Why is that dangerous and what should they use instead?**

Mid: Pod labels are attacker-controlled if the attacker can create pods, so any pod with that label gets the SVID. Use ServiceAccount selectors instead.

Principal: Pod labels are set at pod creation by whoever has RBAC to create pods in the namespace, which in a busy cluster is many teams and often the CI robot account. A hostile tenant creates a pod with `app: payments-api` and the Agent's k8s attestor reads that label through the kubelet, matches the entry, and issues the SVID. The correct selector is `k8s:sa:payments-api` combined with `k8s:ns:payments`, because the projected ServiceAccount token is signed by the API server and the SPIRE k8s attestor verifies it via TokenReview against the API server, not against the pod spec. Even better is combining with `k8s:node-name` if you want per-node scoping, plus `sigstore:*` if you require signed images.

**Q: SPIRE Agent's Workload API socket sits at `/run/spire/agent.sock` and is mounted via hostPath into every pod on the node. Is that OK?**

Mid: No; any pod can talk to it. Use the CSI driver so each pod gets its own socket.

Principal: Any pod on that node can `connect` the socket and be attested. The Agent will run selectors on the caller's PID and issue whatever SVID matches, so if the mix of pods on the node includes a low-trust workload plus a high-trust one, and any registration entry matches the low-trust pod's kernel evidence, the low-trust pod gets a real credential. spire-csi-driver mode fixes this by providing a per-pod bind-mount of a socket whose peer credentials the Agent ties to the pod's ServiceAccount at mount time, so a co-tenant pod cannot even open a socket to talk to. hostPath mode is still deployed in older clusters but should be considered a migration debt, not an acceptable configuration.

**Q: How does SPIFFE federation prevent a compromised CA from impersonating a peer trust domain?**

Mid: Federation uses the peer's own bundle, not Web PKI, so a mis-issued Web PKI cert doesn't grant anything.

Principal: The Federation spec defines two profiles for the bundle endpoint. `web` uses Web PKI to authenticate the endpoint hostname, which means any CA in the fetcher's trust store can issue a cert for that hostname and defeat the check. `https_spiffe` authenticates the endpoint using a SPIFFE ID from a previously known bundle, so the endpoint itself must present an SVID for that identity, and only the peer trust domain's Server can sign it. The initial bootstrap of the peer's bundle happens out-of-band (typically a manifest committed to Git and applied by an operator), so there is no TOFU window a MITM can exploit. Combining `https_spiffe` with out-of-band bootstrap eliminates the Web PKI dependency entirely.

**Q: You're asked to raise the default SVID TTL from 1 hour to 24 hours because rotation is causing brief connection failures in a legacy client. What do you do?**

Mid: Push back and fix the legacy client, because SVID expiry is the only revocation.

Principal: The connection failures are usually a client that caches the SVID and re-uses it past `NotAfter` because it doesn't subscribe to Workload API streaming updates. The go-spiffe TLS integration handles this correctly; the legacy client is likely holding a static cert. Fix the client by wiring it to `workloadapi.X509Source`, which delivers rotated SVIDs before expiry with a jittered lead time (default 5 minutes). If the client is truly unfixable, put an mTLS proxy in front of it (envoy-spire-agent) that terminates SPIFFE mTLS and hands the client a stable stunnel-style TLS connection. Raising TTL to 24 hours makes SVID a durable credential and defeats SPIFFE's revocation model, since compromise remediation becomes "wait a day."

**Q: A JWT-SVID from a legitimate workload is being used to authenticate to a service that workload has no business talking to. How is that possible?**

Mid: The service isn't checking the audience claim, so any JWT-SVID with a valid signature is accepted.

Principal: JWT-SVID is a bearer token; a receiver that validates only signature and `sub` accepts any token any workload in the trust domain can obtain from its own Workload API. The SPIFFE JWT-SVID spec requires the receiver check `aud` against a value the receiver expects, and issuing code must call `FetchJWTSVID(audience=<receiver_id>)`. The failure mode is a shared audience string across many services or a receiver library that treats missing audience as wildcard. Fix in code: pass the exact expected audience to `jwtsvid.ParseAndValidate` and reject if not present. Fix at policy level: mint JWT-SVIDs with per-callee audiences and forbid multi-audience tokens.

**Q: What breaks if the SPIRE Server's signing key is on disk and the Server host is compromised?**

Mid: The attacker can mint SVIDs for any identity in the trust domain until the trust bundle is rotated.

Principal: With a `disk` KeyManager the private key is in the Server's data directory, so an attacker with code execution on the Server reads it and can sign SVIDs forever, even after the Server is remediated, because they have the key. Recovery requires generating a new trust domain root, distributing a new bundle to every workload out-of-band (since the poisoned bundle is served over channels the attacker's key still authenticates), and treating every SVID minted since compromise as suspect. With a KMS KeyManager, the key never leaves KMS; the attacker can sign only while their code runs against the Server's IAM role, and IAM audit logs bound the window. Recovery is scoped to that window, not permanent.

**Q: A SPIRE Agent has been running for 3 months on a node. Is that a problem?**

Mid: Long-running Agents can drift in trust bundle and are hard to reason about; treat them like servers, patch and rotate.

Principal: The Agent itself rotates its own SVID continuously against the Server; the concern is not the Agent's identity. Concern one is bundle drift on the Agent's cache versus the Server, which SPIRE handles via streaming but is worth verifying. Concern two is a compromised Agent binary from months ago that has stale plugin versions and cached selector data. If the node uses `aws_iid` node attestation the Agent's identity is tied to the instance, and terminating the instance forces a fresh Agent bootstrap. Policy: rotate Agent binaries on a cadence, restart Agents when the Server rotates its signing key, and monitor the Agent's cached bundle serial against the Server's current serial.

## War story

In 2023 a large fintech deployed SPIRE across two clusters with federation between them. During a production incident, an engineer with root on a Server host added a registration entry for a debug workload directly on the Server rather than via the GitOps controller, using `k8s:pod-label:role=debug` as the sole selector. The entry stayed in the datastore after the incident. Six weeks later, an unrelated pentest team ran a red-team exercise from a low-privilege developer namespace, created a pod with `role: debug`, hit the Agent's Workload API through the hostPath-mounted socket, and received an SVID for `spiffe://prod/debug/root` that policy in downstream services trusted for arbitrary internal API calls. Recovery required deleting the entry, rotating trust bundles across both federated domains as a precaution (since the SVID had a 12-hour TTL and the team could not be certain it had not been captured), and moving all registration entries into `spire-controller-manager` with a GitOps enforcer that alerted on out-of-band writes. The postmortem cited three of the failures in this doc: pod-label-only selector, hostPath socket exposure, and TTL an order of magnitude longer than incident-response time.

## Sources

<a id="ref1"></a>[1] SPIFFE Specifications: The SPIFFE Identity and Verifiable Identity Document. SPIFFE Project. 2023. https://github.com/spiffe/spiffe/blob/main/standards/SPIFFE.md

<a id="ref2"></a>[2] The X.509 SPIFFE Verifiable Identity Document (X509-SVID) Specification. SPIFFE Project. 2023. https://github.com/spiffe/spiffe/blob/main/standards/X509-SVID.md

<a id="ref3"></a>[3] SPIFFE Workload API Specification. SPIFFE Project. 2023. https://github.com/spiffe/spiffe/blob/main/standards/SPIFFE_Workload_API.md

<a id="ref4"></a>[4] The JWT SPIFFE Verifiable Identity Document (JWT-SVID) Specification. SPIFFE Project. 2023. https://github.com/spiffe/spiffe/blob/main/standards/JWT-SVID.md

<a id="ref5"></a>[5] SPIRE Server Configuration Reference. SPIFFE / SPIRE Documentation. 2024. https://spiffe.io/docs/latest/deploying/spire_server/

<a id="ref6"></a>[6] SPIRE Agent and Workload Attestation. SPIFFE / SPIRE Documentation. 2024. https://spiffe.io/docs/latest/deploying/spire_agent/

<a id="ref7"></a>[7] SPIFFE Federation Specification. SPIFFE Project. 2023. https://github.com/spiffe/spiffe/blob/main/standards/SPIFFE_Federation.md

<a id="ref8"></a>[8] Kubernetes Workload Attestor Plugin. SPIRE plugin reference. 2024. https://github.com/spiffe/spire/blob/main/doc/plugin_agent_workloadattestor_k8s.md

<a id="ref9"></a>[9] SPIFFE CSI Driver. SPIFFE Project. 2024. https://github.com/spiffe/spiffe-csi

<a id="ref10"></a>[10] SPIRE Controller Manager for Kubernetes. SPIFFE Project. 2024. https://github.com/spiffe/spire-controller-manager

<a id="ref11"></a>[11] SPIRE Registration Entry Reference and TTL Semantics. SPIFFE / SPIRE Documentation. 2024. https://spiffe.io/docs/latest/deploying/registering/
