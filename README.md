# waf-fp-test

`waf-fp-test` detects WAF false positives by sending known-benign requests through a WAF and, when possible, directly to the application origin.

## Recommended run mode: YAML config

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
  block_body_contains: []
  block_body_regex: []
  block_header_contains: []

execution:
  timeout: 10s
  rechecks: 2
  max_body_bytes: 1048576

output:
  file: results.jsonl
  summary: summary.md
  baseline: ""
  comparison: comparison.md
  fail_on_new_fp: false
```

The configuration loader supports a small, predictable YAML subset: one top-level level plus one nested section level, scalar values, and inline lists. Unknown keys are rejected.

## CLI fallback and overrides

Explicitly supplied flags override values loaded from YAML. Running without `--config` also remains supported.

```bash
go run ./cmd/waf-fp \
  --config config.yaml \
  --mode waf-only \
  --placements query,json \
  --output emergency-check.jsonl
```

Only run tests against systems you own or are explicitly authorized to test.

## Operating modes

### Differential

The same request is sent through the WAF and directly to the origin:

```text
public hostname -> WAF -> origin
origin IP + HTTP Host + TLS SNI -> origin
```

The direct-origin settings are separated intentionally:

```text
TCP connection -> origin.url
HTTP Host      -> origin.host
TLS SNI        -> origin.sni
```

A response status such as `403` does not, by itself, prove that the WAF generated the response. In the default black-box model, the primary evidence is route comparison: the request is blocked through the WAF route but the same request is not blocked on the direct-origin route. A reproducible difference of this kind is classified as `CONFIRMED_FP`.

### WAF-only

Use this mode when direct origin access is unavailable. A reproducible block is classified as `BLOCKED_BENIGN_CANDIDATE`, not `CONFIRMED_FP`, because there is no direct-origin baseline and therefore no reliable way to identify which component generated the response.

## Block detection

By default, the example configuration uses only configured blocking statuses:

```yaml
detection:
  block_statuses: [403, 406]
  block_body_contains: []
  block_body_regex: []
  block_header_contains: []
```

Body substrings, body regular expressions, and response-header indicators are optional installation-specific signals. Configure them only when the tested environment is known to emit stable markers. The project does not assume any specific WAF product, proxy implementation, `Server` value, or proprietary response header.

Example of a custom header marker known to exist in a particular environment:

```yaml
detection:
  block_header_contains:
    - "X-Company-Security-Decision=deny"
```

This is only an example of the syntax; users must provide markers that are actually verified in their own environment.

Each observation records HTTP status, duration, body SHA-256, captured size, content type, server header, redirect location, and any explicitly configured indicator that matched.

## Reports and baseline comparison

Each run can generate a Markdown summary grouped by verdict and placement:

```yaml
output:
  file: results.jsonl
  summary: summary.md
```

A previous JSONL run can be supplied as a baseline:

```yaml
output:
  baseline: baseline.jsonl
  comparison: comparison.md
  fail_on_new_fp: true
```

Comparison categories include:

- `NEW_FP`;
- `FIXED_FP`;
- `UNCHANGED_FP`;
- `NEW_RESPONSE_DIFFERENCE`.

When `fail_on_new_fp` is enabled, the command exits with a non-zero status if new false positives appear.

## Main verdicts

- `CONFIRMED_FP`;
- `BLOCKED_BENIGN_CANDIDATE`;
- `FLAKY_FP`;
- `RESPONSE_DIFFERENCE`;
- `NOT_FP` / `NOT_BLOCKED`;
- `AMBIGUOUS`;
- `WAF_ERROR` / `ORIGIN_ERROR`.

## Request diversity

The project uses a controlled and reproducible matrix:

```text
benign payload × placement × content type × encoding × method
```

The same benign value can exercise different parsing paths in a query parameter, JSON string, cookie, header, path, or form field. Each combination is recorded separately.

## Echo-origin

Echo-origin remains an optional laboratory component. It can run on any dedicated host or container reachable from the WAF and does not need to be installed on a real production origin.

## Next milestones

1. Validate summary and baseline reports on representative result sets.
2. Import and normalize FP corpora with provenance.
3. Add application profiles and authentication support.
4. Expand request formats with multipart, XML, GraphQL, and nested JSON.
5. Add the optional echo-origin container for controlled environments.
