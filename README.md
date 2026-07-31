# waf-fp-test

`waf-fp-test` detects WAF false positives by sending known-benign requests through a WAF and, when possible, directly to the application origin.

## Recommended run mode: YAML config

Copy the example and edit it for the tested application:

```bash
cp config.example.yaml config.yaml
go run ./cmd/waf-fp --config config.yaml
```

Example:

```yaml
mode: differential

target:
  url: https://app.example.test
  path: /api/search

origin:
  url: https://192.0.2.10:443
  host: app.example.test
  sni: app.example.test

request:
  payloads: examples/payloads.txt
  placements: [query, form, json, header, cookie, path]

detection:
  block_statuses: [403, 406]
  block_body_contains: ["access denied", "request rejected"]

execution:
  timeout: 10s
  rechecks: 2
  max_body_bytes: 1048576

output:
  file: results.jsonl
```

The configuration loader intentionally supports this small, predictable YAML subset: one top-level level plus one nested section level, scalar values, and inline lists. Unknown keys are rejected instead of being silently ignored.

## CLI fallback and overrides

The original flag-based mode remains available. Explicitly supplied flags override values loaded from the configuration file:

```bash
go run ./cmd/waf-fp \
  --config config.yaml \
  --mode waf-only \
  --placements query,json \
  --output emergency-check.jsonl
```

Running without `--config` also remains supported:

```bash
go run ./cmd/waf-fp \
  --mode waf-only \
  --target https://app.example.test \
  --path /api/search \
  --payloads examples/payloads.txt \
  --placements query,json \
  --block-statuses 403,406 \
  --output results.jsonl
```

Only run tests against systems you own or are explicitly authorized to test.

## Operating modes

### Differential

The request is sent through the WAF and directly to the origin. Direct-origin connection address, HTTP Host, and HTTPS TLS SNI are configured separately:

```text
TCP connection -> origin.url
HTTP Host      -> origin.host
TLS SNI        -> origin.sni
```

A reproducible WAF block that is not observed on the direct route is classified as `CONFIRMED_FP`.

### WAF-only

Use this when direct origin access is unavailable. A reproducible block is classified as `BLOCKED_BENIGN_CANDIDATE`, not `CONFIRMED_FP`, because there is no direct-origin baseline.

## Current evidence and verdicts

Each observation records HTTP status, duration, body SHA-256, captured size, content type, server header, redirect location, and a matched block-page substring. Blocking is detected by configured status codes or case-insensitive body signatures.

Main verdicts:

- `CONFIRMED_FP`;
- `BLOCKED_BENIGN_CANDIDATE`;
- `FLAKY_FP`;
- `RESPONSE_DIFFERENCE`;
- `NOT_FP` / `NOT_BLOCKED`;
- `AMBIGUOUS`;
- `WAF_ERROR` / `ORIGIN_ERROR`.

## Request diversity

The project uses a controlled, reproducible matrix rather than random traffic:

```text
benign payload × placement × content type × encoding × method
```

The same benign value can exercise different WAF parsing paths in a query parameter, JSON string, cookie, header, path, or form field. Each combination is recorded separately.

## Echo-origin

Echo-origin remains an optional laboratory component. It can run on any dedicated host or container reachable from the WAF and does not need to be installed on a real production origin.

## Next milestones

1. Add configurable response-header and regular-expression block indicators.
2. Add an optional echo-origin container for controlled environments.
3. Import and normalize FP corpora with provenance.
4. Add summary and baseline-comparison reports.
5. Add application profiles and authentication support.
