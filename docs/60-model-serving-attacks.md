# Model Serving and Inference-API Attacks

> An inference server is a multi-tenant time-sharing kernel for GPUs, and every side channel that ever hurt CPU multi-tenancy re-appears one layer up. The scheduler batches heterogeneous requests to keep tensor cores busy, so any resource whose state is a function of prior requests (KV cache, prefix cache, speculative-draft acceptance state, page-attention block pool) becomes an oracle when latency or token-count is observable to a different tenant. The control plane is worse than the data plane, because Triton, TGI, and vLLM all default to no authentication and rely on the operator to bolt a proxy in front. Model artifacts are executable code in disguise: a Python backend, a custom op library, or a pickle-shaped weight file crosses from "data" to "code" the moment the server loads it, which is why [62-model-file-formats.md](./62-model-file-formats.md) is a hard prerequisite for reasoning about this surface. The framework matters because caching modes, tokenizer placement, and admin surfaces differ per implementation, and the wrong flag flipped in a Helm chart is how a "GPU cluster" turns into a public RCE.

**Interview frequency:** Niche

*See also: [Multi-Tenancy and Isolation](102-multi-tenancy-isolation.md) for the data, compute, and application isolation layers that prevent cross-tenant leakage in shared model-serving infrastructure.*

## Quick reference

Triton Inference Server exposes an unauthenticated model-repository control plane over HTTP. The following request loads an arbitrary model directory from disk into GPU memory on a server that left `--model-control-mode=explicit` enabled without an auth proxy:

```http
POST /v2/repository/models/backdoor/load HTTP/1.1
Host: triton.internal:8000
Content-Type: application/json
Content-Length: 0

HTTP/1.1 200 OK
Content-Length: 0
```

The same server accepts `POST /v2/repository/models/backdoor/unload` and `POST /v2/repository/index`, which lists every model. Pairing this with a writable model store (NFS, S3 with weak IAM, container image with world-writable `/models`) yields RCE via a Python-backend `model.py` executed on the next inference request. Triton's own docs are explicit that the server does not implement authentication and that the operator is responsible for securing access.

A separate wire-level leak is the prompt-cache timing side channel. A vLLM server running with automatic prefix caching returns time-to-first-token (TTFT) that depends on whether the requested prefix already sits in the KV cache from a prior tenant's request:

```
$ time curl -s -X POST http://vllm:8000/v1/completions \
  -H 'Authorization: Bearer $TOKEN' \
  -d '{"model":"llama3-70b","prompt":"SYSTEM: You are the internal HR bot for Acme. Salary bands ...","max_tokens":1}'
{"id":"cmpl-1","choices":[{"text":" ","index":0}], ...}
real  0m0.041s     # cache hit: another tenant recently used this prefix

$ time curl -s -X POST http://vllm:8000/v1/completions \
  -d '{"model":"llama3-70b","prompt":"SYSTEM: You are the internal HR bot for Widgetco. Salary bands ...","max_tokens":1}'
real  0m0.612s     # cache miss: 15x slower, prefix is fresh
```

The delta between 41 ms and 612 ms is the observation channel. An attacker who can probe candidate system prompts learns which one another tenant is currently using.

| Invariant | Where enforced | How violated | Source |
|---|---|---|---|
| Inference endpoints require authenticated caller | Reverse proxy or serving-framework auth middleware | Triton, TGI, vLLM ship auth-off by default and get exposed via NodePort or public LB | <sup>[[3]](#ref3)</sup><sup>[[7]](#ref7)</sup> |
| Admin / model-repository control plane is not exposed to tenants | Network policy, separate listen port, ACL | Triton `/v2/repository/*` on same port as inference; TGI `/info` leaking model path and CUDA version | <sup>[[4]](#ref4)</sup> |
| KV cache and prefix cache are not shared across trust boundaries | Serving framework cache key includes tenant / session id | vLLM `--enable-prefix-caching` keys on token hash only, so identical prefixes across tenants collide | <sup>[[1]](#ref1)</sup><sup>[[2]](#ref2)</sup> |
| Continuous-batch scheduling does not leak per-request timing to co-tenants | Padding, quantized-time scheduling, disable speculative decode across tenants | Orca-style continuous batching lets adjacent requests observe each other's decode cadence | <sup>[[5]](#ref5)</sup><sup>[[12]](#ref12)</sup> |
| Loaded model artifacts are integrity-verified before load | Signed manifests, cosign / Sigstore over the model directory | Bare `model.safetensors` fetched over HTTP with no signature; Python-backend `model.py` executed as trusted code | <sup>[[6]](#ref6)</sup> |
| Tokenizer input length has a hard server-side cap | Request-parser rejects oversize prompts pre-scheduling | Absent cap lets an attacker OOM the scheduler queue or trigger huge KV allocations | <sup>[[7]](#ref7)</sup><sup>[[10]](#ref10)</sup> |
| Speculative decoding draft-model outputs never cross tenant boundaries | Draft KV state segregated per session | Shared draft cache in EAGLE / Medusa setups exposes acceptance-rate timing | <sup>[[8]](#ref8)</sup> |
| Health / metrics endpoints do not disclose model identity or GPU topology | Split port, auth on `/metrics`, redact model names | TGI `/info`, Triton `/v2` returning full model index anonymously | <sup>[[9]](#ref9)</sup> |

## How it works

A modern LLM serving stack has six shared resources, each of which is an isolation boundary that can be broken.

```mermaid
flowchart LR
  Client -->|HTTP/gRPC| Router[Router / API Gateway]
  Router --> Queue[Request Queue]
  Queue --> Sched[Continuous Batch Scheduler]
  Sched --> KV[KV / Prefix Cache Pool]
  Sched --> GPU[GPU Model Weights]
  KV --> Decode[Token Decoder]
  GPU --> Decode
  Decode -->|SSE / gRPC stream| Client
  subgraph Admin
    Repo[/v2/repository or /admin/]
    Info[/info /metrics /health]
  end
  Router -. often same port .-> Admin
  Disk[(Model Store: S3, NFS, PVC)] --> GPU
```

### Request queue and batch scheduler

The request queue is where token-count DoS starts: if the parser accepts a 200 k-token prompt and only rejects it after tokenization, memory has already been spent. The continuous batch scheduler (Orca-style, used by vLLM, TGI, and TensorRT-LLM Triton backend) folds new requests into an in-flight batch on every decode step, which is why request boundaries stop being isolation boundaries in the time domain <sup>[[5]](#ref5)</sup>.

### KV cache and prefix cache

The KV cache stores per-layer key/value tensors keyed by position, and the prefix cache (vLLM `--enable-prefix-caching`, TGI radix cache, TensorRT-LLM `enable_kv_cache_reuse`) additionally hashes token prefixes so a subsequent request sharing a prefix reuses the tensors instead of recomputing them <sup>[[1]](#ref1)</sup>. That reuse is the exact mechanism that turns TTFT into a cross-request oracle.

### Tokenizer and chat templating

The tokenizer is often colocated in the API server process and applies chat templates that inject system prompts before the model ever sees them, so a bug in template rendering (Jinja2 in HF `tokenizer.apply_chat_template`, or vLLM's `chat_template` file loaded via CLI) is a prompt-injection or SSRF primitive before you reach the model.

### Model weights on disk

Model weights on disk are the supply-chain surface described in [62-model-file-formats.md](./62-model-file-formats.md): a Triton `model.py` or a Python-backend model is arbitrary code executed under the server's UID, and safetensors is safe only for the tensor payload, not for adjacent files.

### Output stream

The output stream matters because SSE and gRPC streaming reveal per-token timing, and per-token timing is the leakage channel for speculative decoding, batch-mate interference, and prefix-cache hit/miss even when TTFT is masked. Speculative decoding (Medusa, EAGLE, `spec-decoding` in vLLM, TGI's draft-model mode) runs a small draft model whose acceptance rate depends on the target's output distribution, and the acceptance rate is visible from token cadence <sup>[[8]](#ref8)</sup>.

### Per-implementation notes

**vLLM**: OpenAI-compatible HTTP on `/v1/completions` and `/v1/chat/completions`; `--api-key` is optional; prefix caching is global across all requests to the same engine unless `--no-enable-prefix-caching` is passed; `--allowed-origins` controls CORS; `--chat-template` loads a Jinja template from disk. Prometheus metrics on `/metrics` include per-request latency histograms that themselves leak.

**Hugging Face TGI**: HTTP on `/generate`, `/generate_stream`, `/v1/*`; `/info` returns model id, quantization, max-batch-total-tokens, sha of the loaded revision; `--hostname 0.0.0.0` is the default in the Docker image; auth is a bearer token only if `HF_API_TOKEN` is set and a proxy enforces it.

**Triton Inference Server**: HTTP on 8000, gRPC on 8001, metrics on 8002 by default; `/v2/repository/*` is control plane on the SAME port 8000 as inference; `--model-control-mode=explicit` allows load / unload; Python backend and DALI backend execute arbitrary Python; `strict-model-config=false` means schema is inferred from the model file.

**TensorRT-LLM**: usually wrapped by Triton via the `tensorrt_llm` backend or via `trtllm-serve` (Triton-agnostic OpenAI-shaped HTTP). Engines are architecture-specific, and `enable_kv_cache_reuse` opts into prefix caching with the same cross-request implications as vLLM.

The security posture of each is dominated by defaults that assume a trusted cluster network, so exposure via NodePort, LoadBalancer, or "just port-forward for a demo" is where most incidents come from.

## Attack techniques

### 1. Prompt-cache timing oracle across tenants

vLLM, TGI, and TensorRT-LLM all support prefix caching, where the KV tensors of a token prefix are memoized and reused across requests. Cache keys are typically a hash of the token id sequence, with no tenant, session, or auth-principal component. When tenant A sends a prompt whose prefix matches tenant B's earlier prompt, tenant A observes a large TTFT reduction, and the reduction is directly measurable <sup>[[1]](#ref1)</sup><sup>[[2]](#ref2)</sup>.

The wire-level example above shows a 15x TTFT delta on a 40-token system-prompt guess against a vLLM server. A refined attack sends candidate system prompts in a binary-search over sensitive substrings (org name, employee id, doc id embedded in the retrieval context) and reads out the secret bit-by-bit from TTFT. Prior work on auditing prompt caches demonstrates detectable prompt-cache side channels with prior-prompt inference against production LLM APIs, including OpenAI, Anthropic, and shared vLLM-style deployments <sup>[[2]](#ref2)</sup>.

Confirm by sending the same prompt twice: hit-then-hit should be fast-fast; hit-then-miss (after an eviction wait or an eviction-inducing filler prompt) should be fast-slow. If TTFT is masked by streaming, use inter-token latency of the first decode step (the prefill boundary is still visible as a burst-vs-steady pattern) or use metrics endpoints if exposed (`/metrics` histograms). An alternative confirmation via inter-token latency alone applies when TTFT is smoothed <sup>[[12]](#ref12)</sup>.

Escalation is cross-tenant inference of system prompts, retrieved-context documents, and PII embedded in RAG contexts. In a multi-org SaaS running one shared vLLM engine, this collapses tenant isolation entirely <sup>[[2]](#ref2)</sup>. Chain with [30-web-llm-attacks.md](./30-web-llm-attacks.md) prompt-injection payloads to weaponize recovered system prompts.

### 2. Continuous-batch adjacent-request timing leak

Orca-style continuous batching interleaves decode steps of concurrent requests within a single GPU launch <sup>[[5]](#ref5)</sup>. Per-step latency of request R depends on the batch size and on whether batch-mates hit prefix cache, are in prefill vs decode, or trigger paging in the block manager. An attacker who owns one request in the batch observes co-tenants' state by watching their own token cadence <sup>[[12]](#ref12)</sup>.

An attacker holds open a long low-`max_tokens` request and time-stamps every SSE `data:` frame. When a co-tenant's high-cost prefill lands in the same iteration, the attacker's inter-token gap widens by tens of milliseconds. Repeating the measurement across many windows recovers a signal about co-tenant request length and prompt structure. Confirm by running two attacker-controlled requests in parallel: injecting a known prefill into one produces the predicted gap widening in the other. If only aggregate throughput is exposed, spam short probe requests and fit a queue model.

Escalation is tenant fingerprinting, request-length disclosure, and, chained with dictionary knowledge of the target's application, guessing which template or endpoint a co-tenant is using. Lower severity than technique 1 by itself, useful as a covariate for the prompt-cache attack.

### 3. Token-count oracle via streaming stop and usage fields

The OpenAI-compatible streaming protocol emits `usage` (or per-token deltas) at the end of a completion; TGI's `/generate` returns `generated_tokens`. When a shared endpoint enforces per-tenant rate limits or per-model quotas by tokens, side effects (429 boundaries, quota-remaining headers) leak the token count of prior requests to co-tenants sharing a bucket.

An attacker binary-searches their own request length against the shared quota until they receive 429, then infers other tenants' cumulative token usage from the delta between their sent tokens and the quota threshold <sup>[[10]](#ref10)</sup>. Confirm by controlled bursts against a known-idle window vs a suspected-busy window; a smaller allowed burst confirms co-tenant consumption. Blind variant: correlate 429s with wall-clock time of day.

Escalation is traffic-pattern deanonymization; combined with prompt-cache timing, it narrows candidate prefixes for the timing oracle.

### 4. Unauthenticated Triton model-repository RCE

Triton with `--model-control-mode=explicit` exposes `POST /v2/repository/models/{name}/load`, `POST /v2/repository/models/{name}/unload`, and `POST /v2/repository/index` on port 8000. There is no built-in authentication. If the model directory is writable (S3 bucket with wildcard put, misconfigured NFS, PVC exposed to a compromised sidecar) or if an attacker can register a symlinked path, the loaded model can be a Python-backend model whose `model.py` is arbitrary Python executed inside the server process <sup>[[3]](#ref3)</sup><sup>[[4]](#ref4)</sup>. See [62-model-file-formats.md](./62-model-file-formats.md) for the equivalent primitives in file-level attacks.

Drop a directory `evil/1/model.py` containing `class TritonPythonModel: ...` with `subprocess.check_output(...)` in its `initialize` method, then:

```
curl -X POST http://triton:8000/v2/repository/models/evil/load
```

Triton loads it, executes `initialize`, and the payload runs as the server UID with GPU access. Confirm exposure with `curl http://target:8000/v2/repository/index`, which returns 200 with a JSON list if the control plane is exposed. Blind: `POST /v2/repository/index` with `ready` filter returns non-empty on any Triton, even without a model list. TGI equivalent: `GET /info` returns `model_id`, `sha`, `docker_label` anonymously <sup>[[9]](#ref9)</sup>.

Escalation is full RCE inside the serving pod, GPU access, credentials in `/proc/self/environ`, IMDS from EC2/GKE, lateral movement across the cluster. Kubernetes ServiceAccount tokens mounted in the pod turn this into cluster-level compromise.

### 5. Malicious model artifact via Python backend or custom op

Loading a model executes code whenever the backend supports code loading. Triton Python backend, Triton PyTorch backend loading a scripted graph with custom ops, TorchServe custom handlers, and vLLM's `--tokenizer` pointing at a HF repo that ships `tokenizer.py` with `trust_remote_code=True` all cross the data/code boundary <sup>[[3]](#ref3)</sup><sup>[[6]](#ref6)</sup>. Cross-link to [62-model-file-formats.md](./62-model-file-formats.md) for the full artifact taxonomy.

A Hugging Face repository containing a `configuration.py` with a `__reduce__` payload will execute in-process when vLLM starts with `--trust-remote-code`. MITRE ATLAS AML.T0010 (AI Supply Chain Compromise) covers this technique explicitly <sup>[[6]](#ref6)</sup>. Read `--trust-remote-code` from process listing, TGI `/info`, or Kubernetes ConfigMap to confirm exposure. Blind: probe timing of first-load; models with remote code have distinctive import-time signatures.

Escalation is the same as technique 4, RCE inside the serving process.

### 6. Speculative-decoding acceptance-rate side channel

Speculative decoding proposes tokens from a small draft model, then verifies with the target; the acceptance rate depends on target-output distribution and thus on the target-request context. When a shared draft cache or shared draft model is used across sessions, the acceptance pattern (visible as bursts of accepted tokens vs single-token verifies) leaks information about co-tenant outputs <sup>[[8]](#ref8)</sup>.

An attacker requests a completion known to correlate with a target's suspected topic; measures inter-token cadence; higher-frequency bursts indicate the draft is well-tuned to the shared distribution, meaning the target's context matches the draft's expectation. Compare cadence with and without speculative decoding enabled (via a flag flip or a canary deployment) to confirm. When streaming is proxy-buffered and cadence is invisible, correlate end-to-end completion latency of a canary account's fixed-length probe workload against a matched probe against a speculative-off canary deployment, and look for a bimodal completion-time distribution keyed on suspected co-tenant workload class <sup>[[8]](#ref8)</sup>.

Signal quality is lower than technique 1 and stacks with it. Primary defense value is knowing this channel exists when reviewing a "we turned on Medusa for latency" change.

### 7. Unbounded prompt / max_tokens DoS

Without `--max-model-len`, `--max-num-batched-tokens`, and a request-level `max_tokens` cap, a single request can allocate multi-GB of KV cache, evict every other tenant's cache entries, and stall the batcher <sup>[[7]](#ref7)</sup><sup>[[10]](#ref10)</sup>. TGI `--max-input-tokens` and Triton per-model config `max_batch_size` are the equivalent knobs.

Send `prompt=A * 100000, max_tokens=8192` on a server with 128k context; observe every co-tenant's TTFT spike into seconds. Confirm by sending progressively larger prompts and recording when 4xx begins; if it never begins, the cap is missing. Blind confirmation reads public `/metrics` for `vllm:num_preemptions_total`.

Escalation is cross-tenant DoS, cost inflation, and incident-noise cover for stealthier attacks (OWASP LLM10 Unbounded Consumption <sup>[[10]](#ref10)</sup>).

### 8. Info-endpoint disclosure and model fingerprinting

TGI `/info`, Triton `/v2` and `/v2/models`, vLLM `/v1/models` and `/metrics` all leak model identity, quantization, revision sha, GPU topology, and sometimes chat-template file paths <sup>[[3]](#ref3)</sup><sup>[[9]](#ref9)</sup>. Combined with public CVE feeds against the loaded runtime versions, this hands the attacker a version-specific exploit list.

For example, `curl -s http://target:8080/info | jq` on a stock TGI returns `{"model_id":"meta-llama/Meta-Llama-3-70B-Instruct","model_sha":"...","docker_label":"sha-abc123","max_batch_total_tokens":163840,...}`. These endpoints are anonymous by default. Blind: rate-limited timing on `/health` still discloses server type by response shape.

Escalation is recon that enables techniques 4, 5, 6 and off-the-shelf CVE exploitation.

## Defense

### Real fix

1. **Terminate authentication and authorization outside the serving process.** The serving container listens only on `127.0.0.1` or on a mesh sidecar's UDS. All ingress goes through an authenticated proxy (Envoy with OIDC, Istio AuthorizationPolicy, or a purpose-built gateway) that enforces per-tenant identity and rate limits <sup>[[3]](#ref3)</sup>. This kills technique 4 (Triton control plane), technique 8 (info disclosure), and gives an enforcement point for technique 3 (per-tenant quotas). Common wrong implementation: enabling `--api-key` on vLLM and calling it done; API keys without per-tenant scoping still allow one tenant to observe another. OWASP ASVS V4.1 (Access Control) applies unchanged to inference <sup>[[10]](#ref10)</sup>.

2. **Disable prefix caching across trust boundaries.** For any endpoint serving multiple tenants (or multiple end users of a shared system prompt product), run with `--no-enable-prefix-caching` on vLLM, disable TensorRT-LLM `enable_kv_cache_reuse`, and set TGI radix cache off. Auditing work on prompt caching shows this is the only reliable mitigation against technique 1 <sup>[[2]](#ref2)</sup>. If caching is needed for latency, partition engines per tenant (one vLLM instance per trust domain) and route by identity <sup>[[1]](#ref1)</sup><sup>[[2]](#ref2)</sup>. Common wrong implementation: keying the cache on `session_id` from the client; the client controls it, so a malicious tenant sets it to a victim's id and gets the same collision. The invariant is that cache keys must include a server-derived, non-forgeable tenant principal. Cross-tenant state isolation for generative-AI services is called out in NIST SP 800-218A PW.7 and is the normative anchor for this control <sup>[[11]](#ref11)</sup>.

3. **Isolate the control plane from the data plane.** Bind Triton `/v2/repository/*` and TGI `/info` to a separate listener on a separate network policy, and reject those paths at the ingress proxy for tenant traffic. Set `--model-control-mode=none` (or `poll` with a signed manifest) in production Triton <sup>[[3]](#ref3)</sup>. This closes technique 4 and drops technique 8 to internal-only. Common wrong implementation: relying on "we don't advertise the endpoint," which loses to a single Nmap scan.

4. **Signed and pinned model artifacts.** Every model directory has a Sigstore-signed manifest listing every file hash. The serving container refuses to load unless verification passes against a set of trusted signers. This is the fix for techniques 4 and 5, and is the same primitive described in [62-model-file-formats.md](./62-model-file-formats.md) <sup>[[6]](#ref6)</sup>. Set `trust_remote_code=False` on all HuggingFace loads unless the specific revision is signed and reviewed. MITRE ATLAS AML.T0010 (AI Supply Chain Compromise) <sup>[[6]](#ref6)</sup>.

5. **Hard input caps enforced before scheduling.** Reject at HTTP-parse time: `Content-Length` cap, JSON body cap, `prompt` token cap after tokenization but before queue insertion, `max_tokens` cap, `n` and `best_of` caps <sup>[[7]](#ref7)</sup><sup>[[10]](#ref10)</sup>. On vLLM, set `--max-model-len` to the real deployed context, `--max-num-batched-tokens` to a value bounded by GPU memory, and enforce a per-request `max_tokens` at the gateway. Common wrong implementation: enforcing only at the model layer, which means the tokenizer already ran on the attacker's payload.

6. **Per-tenant quota buckets that do not leak.** Rate-limit buckets keyed on authenticated tenant, not on IP; return the same shape of 429 regardless of remaining quota; do not include `x-ratelimit-remaining` on shared buckets <sup>[[10]](#ref10)</sup>. Kills technique 3.

### Defense in depth

1. **Speculative decoding scoped per session.** If Medusa or draft-model speculative decoding is enabled, verify the draft KV state is not shared across sessions, and consider disabling for tenant-mixed engines <sup>[[8]](#ref8)</sup>. Fallback: monitor cadence variance externally as a canary.

2. **Batch-mate isolation via padding.** For high-value single-tenant endpoints, disable continuous batching (batch size 1) or run with quantized-time scheduling that pads per-step latency <sup>[[5]](#ref5)</sup><sup>[[12]](#ref12)</sup>. Costly in throughput; used only where the leak is unacceptable.

3. **Metrics endpoint hardening.** `/metrics` behind auth; strip per-request labels that could deanonymize traffic (per-request latency histograms bucketed by tenant are especially dangerous). Kills the blind variants of techniques 2 and 7.

4. **Runtime sandboxing of the serving process.** Run Triton, vLLM, or TGI under a strict seccomp profile, no CAP_SYS_PTRACE, no `/proc` access to other processes, no outbound network to IMDS. If technique 4 or 5 hits, the blast radius stays in the pod.

5. **Continuous supply-chain scanning of the model store.** Scheduled scan of the model bucket for unauthorized diffs, new `.py` files, unexpected `trust_remote_code` uses. Ties to [62-model-file-formats.md](./62-model-file-formats.md) <sup>[[6]](#ref6)</sup>.

## Detection and telemetry

- Log every model load and unload with actor identity, source URI, and manifest hash. A load event from anywhere other than the deploy pipeline is an incident.
- Alert on any external ingress to `/v2/repository/*` (Triton) or `/info` (TGI) reaching the pod. These endpoints should only ever be hit by localhost or a specific admin CIDR.
- Track TTFT distribution per model per tenant. A bimodal distribution with a low-latency cluster far below the prefill-time floor is the fingerprint of prefix-cache hits, and a spike of hits from one tenant with no prior context of that shape is a candidate probe of the prompt-cache oracle.
- Track token cadence variance during periods of low tenant count. An anomalous variance is a candidate speculative-decoding side-channel probe.
- Alert on `vllm:num_preemptions_total` spikes, `vllm:gpu_cache_usage_perc` staying pinned near 100 percent, or Triton `nv_inference_queue_duration_us` right-tail excursions. These correlate with unbounded-consumption abuse.
- Canary shape: a synthetic tenant that periodically probes its own TTFT against a fixed prompt and alerts on drift. If TTFT changes materially without a code change on your side, someone else warmed your cache.
- Retain per-request auth principal, model name, prompt token count, output token count, and total wall time. Retain nothing that reveals prompt content to the logging tier unless a hashed digest is sufficient.

Prometheus and OpenTelemetry hooks are documented for vLLM (`/metrics`), TGI (Prometheus endpoint), and Triton (metrics port 8002). Use them, do not expose them past the mesh.

## Interviewer probes

**Q1.** vLLM ships with prefix caching enabled by default in recent releases. What is the risk in a multi-tenant SaaS, and what is the fix?

Mid: it can leak prompts across tenants; disable it.
Principal: the cache key hashes token ids without a server-derived tenant principal, so tenants sharing prefix content collide, and TTFT deltas of hundreds of milliseconds convert into a binary-search oracle over candidate prefixes <sup>[[2]](#ref2)</sup>. Fix is engine partitioning per trust domain, plus `--no-enable-prefix-caching` on any engine that must be shared; keying on a client-supplied session id fails because the client controls it. Related disclosure: coordinated disclosure to major LLM API providers in 2024 documented the same class of leak against production commercial APIs. This is a case where "auth is off by default" is not the whole story; principal answers distinguish control plane vs data plane vs metrics plane and separate auth from tenant-scoped isolation of shared state (KV cache, prefix cache, draft cache, quota buckets).

**Q2.** You inherit a Triton deployment reachable at `triton.internal:8000`. Where do you look first?

Mid: check auth.
Principal: `curl http://triton.internal:8000/v2/repository/index` and `curl http://triton.internal:8000/v2/models`. If control plane is on the inference port, that is the emergency. Confirm `--model-control-mode` and whether the model store is writable by anything the network can reach <sup>[[3]](#ref3)</sup>. Failure mode: RCE via a planted Python backend; defense trade-off is that `--model-control-mode=explicit` is convenient for hot-reload and that convenience is the whole vulnerability. The proxy must be the enforcement point for tenant identity, must strip control-plane paths, and must not proxy metrics; the serving container must bind to loopback so the proxy is not bypassable via NodePort exposure.

**Q3.** How would speculative decoding leak information across tenants?

Mid: it is a performance feature, it does not leak.
Principal: acceptance rate of the draft model depends on the target's output distribution, and token cadence encodes acceptance rate. When the draft model or its KV state is shared across sessions, an attacker on one session observes cadence perturbations that correlate with co-tenant output structure <sup>[[8]](#ref8)</sup>. Invariant violated: draft state must be per-session. Mitigation: disable for tenant-mixed engines, or scope the draft KV cache per request.

**Q4.** A team argues that `trust_remote_code=True` is fine because the model is from Hugging Face. Convince them otherwise.

Mid: HF is a public registry, anyone can upload malicious code.
Principal: the flag executes `configuration.py` or `modeling_*.py` from the model repo in-process at load time; a pinned revision is not a signature; a malicious update to a mirror or an account takeover is enough. MITRE ATLAS AML.T0010 (AI Supply Chain Compromise) covers this technique class <sup>[[6]](#ref6)</sup>. Fix is signed manifests and a load-time verifier; the design principle is described in [62-model-file-formats.md](./62-model-file-formats.md). Real incident: security researchers disclosed roughly 100 malicious models on the Hugging Face Hub in early 2024 that abused pickle deserialization to gain code execution on downloader machines. Specific code paths that execute untrusted content at load time include the Triton Python backend, HF `trust_remote_code`, TorchServe custom handlers, and custom TensorRT plugins.

**Q5.** Design a rate limit for a shared inference endpoint that resists side-channel deanonymization.

Mid: 100 requests per minute per API key.
Principal: buckets keyed on server-derived tenant principal, quantized in time and normalized in shape so response timing is independent of remaining budget; do not surface remaining-budget headers on shared buckets; enforce both request-count and token-count limits and pre-tokenize before admitting to the batcher; align rejection latency to a floor so 429 timing does not disclose queue depth <sup>[[10]](#ref10)</sup>. Failure mode caught: token-count oracle plus unbounded consumption. Four different limits must all exist: `max-model-len`, `max-num-batched-tokens`, per-request `max_tokens`, and per-tenant token/minute.

**Q6.** How do you tell whether a TTFT anomaly is a prefix-cache leak versus a cold-start?

Mid: warm the model and re-measure.
Principal: run a synthetic tenant with a fixed prompt and record TTFT continuously; compare against a matched-length prompt with a randomized suffix. A cache hit reproduces on the same prefix and disappears on eviction; a cold-start reproduces at deployment boundaries and correlates with the first N requests after a rolling restart. If the "hit" pattern appears without a matching prior request from your own tenant, another tenant warmed your cache <sup>[[2]](#ref2)</sup>.

**Q7.** Continuous batching is described in the Orca paper. Why does it break the "requests are isolated" assumption?

Mid: because they run at the same time.
Principal: continuous batching folds new requests into an in-flight batch at every decode step, so per-step latency for request R is a function of the current set of batch-mates and their prefill/decode positions <sup>[[5]](#ref5)</sup>. That function is observable to R, so any state that varies with batch composition is a covert channel. Isolation must be either time-domain (batch size 1, padding) or trust-domain (batch-mate co-tenancy restricted by identity). Prompt injection is orthogonal to serving-layer attacks and is covered in [30-web-llm-attacks.md](./30-web-llm-attacks.md); serving-layer defenses do not stop prompt injection and vice versa.

**Q8.** A pen test finds `/info` on your TGI returning full model metadata. Priority?

Mid: hide it.
Principal: medium severity as recon; the underlying invariant that fails is "no unauthenticated endpoint discloses fleet composition." Fix at the ingress: strip `/info`, `/metrics`, `/v2*` from tenant-reachable paths; require auth on the internal admin path; audit for other frameworks doing the same (Triton `/v2/models`, vLLM `/v1/models` and `/metrics`) <sup>[[9]](#ref9)</sup>. This is a lightweight variant of the class captured by OWASP ASVS "Verify sensitive data is not disclosed via error messages or metadata."

## War story

In September 2024, a preprint on timing side channels in LLM serving established that continuous-batching schedulers in shared LLM serving systems produce recoverable timing side channels observable by a co-tenant <sup>[[12]](#ref12)</sup>. Follow-on work on auditing prompt caching in February 2025 extended the result to prompt caching specifically, demonstrating detectable cross-user prompt-cache leakage on production commercial APIs, with coordinated disclosure to affected vendors <sup>[[2]](#ref2)</sup>. Several providers responded by moving to per-user caches or by disabling prefix caching on multi-tenant tiers. The defender takeaway is that a feature promoted for latency (prefix caching) crossed a trust boundary silently, was measurable from a normal customer account, and remained latent in production because standard security scanning does not model timing-based cross-tenant leakage. Any deployment currently running shared prefix caching across tenants should treat this as a live exposure until partitioned.

## Sources

<a id="ref1"></a>[1] vLLM Documentation, Automatic Prefix Caching design. vLLM Project. Current. https://docs.vllm.ai/en/latest/design/automatic_prefix_caching.html
<a id="ref2"></a>[2] Auditing Prompt Caching in Language Model APIs. arXiv:2502.07776. 2025. https://arxiv.org/abs/2502.07776
<a id="ref3"></a>[3] Triton Inference Server, Secure Deployment Considerations. NVIDIA. Current main branch. https://github.com/triton-inference-server/server/blob/main/docs/customization_guide/deploy.md
<a id="ref4"></a>[4] Triton HTTP/REST and gRPC Protocol (V2 implementation of the KServe V2 inference protocol). NVIDIA. Current. https://github.com/triton-inference-server/server/blob/main/docs/protocol/README.md
<a id="ref5"></a>[5] Orca: A Distributed Serving System for Transformer-Based Generative Models. USENIX OSDI 2022. https://www.usenix.org/conference/osdi22/presentation/yu
<a id="ref6"></a>[6] MITRE ATLAS Technique AML.T0010 AI Supply Chain Compromise. MITRE ATLAS data. Current. https://github.com/mitre-atlas/atlas-data/blob/main/data/techniques/AML.T0010.yaml
<a id="ref7"></a>[7] vLLM OpenAI-Compatible Server, CLI reference and engine args. vLLM Project. Current. https://docs.vllm.ai/en/latest/serving/openai_compatible_server.html
<a id="ref8"></a>[8] When Speculation Spills Secrets: Side Channels via Speculative Decoding In LLMs. arXiv:2411.01076. 2024. https://arxiv.org/abs/2411.01076
<a id="ref9"></a>[9] Text Generation Inference OpenAPI reference. Hugging Face. Current. https://huggingface.co/docs/text-generation-inference/reference/api_reference
<a id="ref10"></a>[10] OWASP Top 10 for Large Language Model Applications, 2025 edition. OWASP Foundation. 2024-11. https://genai.owasp.org/llm-top-10/
<a id="ref11"></a>[11] NIST SP 800-218A, Secure Software Development Practices for Generative AI and Dual-Use Foundation Models. NIST. 2024-07. https://csrc.nist.gov/pubs/sp/800/218/a/final
<a id="ref12"></a>[12] The Early Bird Catches the Leak: Unveiling Timing Side Channels in LLM Serving Systems. arXiv:2409.20002. 2024. https://arxiv.org/abs/2409.20002
