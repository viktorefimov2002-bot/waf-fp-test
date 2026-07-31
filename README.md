# waf-fp-test

`waf-fp-test` is an early-stage framework for detecting WAF false positives by comparing the same benign request through a WAF and directly against the origin.

## Current prototype

The current prototype implements:

- benign payloads loaded from a text file;
- controlled placements: query, form, JSON, header, cookie, and path;
- a request through the WAF and a direct-origin baseline request;
- an optional direct-origin HTTP `Host` override for virtual hosting;
- `X-WAF-FP-Test-ID` correlation IDs;
- configurable blocking status codes;
- automatic rechecks for candidate false positives;
- JSONL results with `CONFIRMED_FP`, `FLAKY_FP`, `NOT_FP`, `AMBIGUOUS`, `WAF_ERROR`, or `ORIGIN_ERROR` verdicts.

## Run

```bash
go run ./cmd/waf-fp \
  --target https://app.example.test \
  --origin http://192.0.2.10:8080 \
  --origin-host app.example.test \
  --path /anything \
  --payloads examples/payloads.txt \
  --placements query,form,json,header,cookie,path \
  --rechecks 2 \
  --block-statuses 403,406 \
  --output results.jsonl
```

`--target` is the public hostname whose DNS points to the WAF. `--origin` is the address used for the direct request that bypasses the WAF. When several virtual hosts share the origin IP, `--origin-host` sets the HTTP `Host` field only for that direct-origin request.

For HTTPS direct-origin requests, changing the HTTP `Host` field does not by itself change TLS SNI or certificate verification. Until explicit SNI and dial-address support is added, prefer an HTTP origin listener for laboratory tests or ensure that the HTTPS endpoint is valid for the address used in `--origin`.

Only run tests against systems you own or are explicitly authorized to test.

## Why request diversity matters for false positives

Diversity is important because WAF rules inspect different request collections and parsing paths. The same benign value can pass in a query parameter but be blocked in JSON, a cookie, a header, a path segment, or a multipart filename.

The goal is not uncontrolled random traffic. The project uses a reproducible test matrix:

```text
benign payload × placement × content type × encoding × method
```

Each expansion must preserve a known-benign semantic context and record exactly which dimension caused the result.

## Operating modes

### Existing application, black-box mode

This is the expected practical mode when there is no access to origin logs or application internals:

```text
runner -> public domain -> WAF -> application origin
runner -> origin IP with Host override -> application origin
```

The tool compares observable responses. This can identify strong FP candidates, but without origin telemetry it cannot prove delivery to the application with absolute certainty. Future versions will therefore also compare response headers, body fingerprints, redirects, and configurable block-page markers instead of relying only on status codes.

### Controlled echo-origin mode

An echo-origin is an optional dedicated backend for a laboratory or acceptance environment. It does not have to run on the production origin server. It can run on any host or container reachable from the WAF and is configured as the backend for a dedicated test hostname.

```text
fp-test.example.test -> WAF -> dedicated echo-origin
```

It returns and optionally records how the request was received: method, path, query, selected headers, cookies, content type, body hash, and correlation ID. This mode gives a stronger oracle and is useful for validating the runner and comparing WAF configurations. It is not required for black-box checks against existing applications.

## Next milestones

1. Record response fingerprints and configurable block-page indicators.
2. Add explicit TLS SNI and dial-address separation for direct HTTPS origin access.
3. Add an optional echo-origin container for controlled environments.
4. Import and normalize false-positive corpora with provenance.
5. Add summary and baseline comparison reports.
