# waf-fp-test

`waf-fp-test` detects WAF false positives by sending known-benign requests through a WAF and, when possible, directly to the application origin.

## Current prototype

The current prototype supports:

- controlled placements: query, form, JSON, header, cookie, and path;
- `X-WAF-FP-Test-ID` correlation IDs;
- automatic rechecks of FP candidates;
- HTTP status and block-page signature detection;
- response fingerprints: body SHA-256, captured size, content type, server, and redirect location;
- separate direct-origin connection address, HTTP Host, and HTTPS TLS SNI;
- differential and WAF-only operating modes;
- JSONL output with verdict and confidence.

Only run tests against systems you own or are explicitly authorized to test.

## Differential mode

Use this mode when the origin can be reached directly:

```bash
go run ./cmd/waf-fp \
  --mode differential \
  --target https://app.example.test \
  --origin https://192.0.2.10 \
  --origin-host app.example.test \
  --origin-sni app.example.test \
  --path /api/search \
  --payloads examples/payloads.txt \
  --placements query,form,json,header,cookie,path \
  --rechecks 2 \
  --block-statuses 403,406 \
  --block-body-contains "access denied,request rejected" \
  --output results.jsonl
```

The direct-origin settings are intentionally separate:

- `--origin` is the actual connection address, including the origin IP and port;
- `--origin-host` is the HTTP `Host` field used for virtual-host routing;
- `--origin-sni` is the TLS SNI name and certificate name used for HTTPS.

This is equivalent in intent to using `curl --resolve`: connect to a selected IP while retaining the application's hostname at the HTTP and TLS layers.

A reproducible WAF block that is not observed on the direct route is classified as `CONFIRMED_FP`. A response difference without a positive block signal is reported separately as `RESPONSE_DIFFERENCE`; it is not automatically called an FP.

## WAF-only mode

Use this mode when direct origin access is unavailable:

```bash
go run ./cmd/waf-fp \
  --mode waf-only \
  --target https://app.example.test \
  --path /api/search \
  --payloads examples/payloads.txt \
  --placements query,json \
  --block-statuses 403,406 \
  --block-body-contains "access denied,request rejected" \
  --output results.jsonl
```

A reproducible block is classified as `BLOCKED_BENIGN_CANDIDATE`, not `CONFIRMED_FP`, because the tool cannot compare it with a direct-origin baseline. This mode is useful for production-like environments, but its evidence is weaker and should be combined with known endpoint behavior or WAF event data when available.

## Response evidence

Each observation stores:

- status code and duration;
- SHA-256 of the captured response body;
- captured response size, limited by `--max-body-bytes`;
- `Content-Type`, `Server`, and `Location`;
- the configured block-page substring that matched, if any.

Blocking is detected when either a configured block status or a configured body signature matches. Body signatures are case-insensitive.

## Verdicts

- `CONFIRMED_FP`: WAF blocked a benign request while the direct origin did not.
- `BLOCKED_BENIGN_CANDIDATE`: WAF-only mode observed a likely block.
- `FLAKY_FP`: the candidate was not reproduced consistently during rechecks.
- `RESPONSE_DIFFERENCE`: WAF and origin responses differ without a clear block signal.
- `NOT_FP` / `NOT_BLOCKED`: no FP block was observed.
- `AMBIGUOUS`: both routes appeared blocked.
- `WAF_ERROR` / `ORIGIN_ERROR`: the corresponding request could not be evaluated.

## Why request diversity matters

The project uses a controlled, reproducible matrix rather than random traffic:

```text
benign payload × placement × content type × encoding × method
```

The same benign value can exercise different WAF parsing paths in a query parameter, JSON string, cookie, header, path, or form field. Each combination is recorded separately so the triggering context remains identifiable.

## Echo-origin

An echo-origin remains an optional laboratory component. It does not need to be installed on a real production origin. It can run on any dedicated host or container reachable from the WAF and be configured as the backend of a test hostname:

```text
fp-test.example.test -> WAF -> dedicated echo-origin
```

It is useful for validating request delivery and parser behavior, but it is not required for black-box differential or WAF-only testing.

## Next milestones

1. Add configurable response-header and regular-expression block indicators.
2. Add an optional echo-origin container for controlled environments.
3. Import and normalize FP corpora with provenance.
4. Add summary and baseline-comparison reports.
5. Add application profiles and authentication support.
