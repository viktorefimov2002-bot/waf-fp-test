# waf-fp-test

`waf-fp-test` is an early-stage framework for detecting WAF false positives by comparing the same benign request through a WAF and directly against the origin.

## Current prototype

The first stage implements:

- benign payloads loaded from a text file;
- injection into a query-string value;
- a request through the WAF and a direct-origin baseline request;
- `X-WAF-FP-Test-ID` correlation IDs;
- configurable blocking status codes;
- JSONL results with `CONFIRMED_FP`, `NOT_FP`, `AMBIGUOUS`, `WAF_ERROR`, or `ORIGIN_ERROR` verdicts.

## Run

```bash
go run ./cmd/waf-fp \
  --target https://waf.example.test \
  --origin http://10.0.0.20:8080 \
  --path /anything \
  --payloads examples/payloads.txt \
  --block-statuses 403,406 \
  --output results.jsonl
```

Only run tests against systems you own or are explicitly authorized to test.

## Why request diversity matters for false positives

Diversity is important because WAF rules inspect different request collections and parsing paths. The same benign value can pass in a query parameter but be blocked in JSON, a cookie, a header, a path segment, or a multipart filename.

The goal is not uncontrolled random traffic. The project will use a reproducible test matrix:

```text
benign payload × placement × content type × encoding × method
```

For the first stage, the scope is intentionally limited to a query value. Planned next placements are form fields, JSON strings, headers, cookies, paths, and multipart fields. Each expansion must preserve a known-benign semantic context and record exactly which dimension caused the result.

## Next milestones

1. Add POST form and JSON request variants.
2. Add repeated rechecks for candidate false positives.
3. Add an echo-origin container that records correlation IDs.
4. Import and normalize false-positive corpora with provenance.
5. Add summary and baseline comparison reports.
