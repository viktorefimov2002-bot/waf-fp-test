# waf-fp-test

`waf-fp-test` searches for WAF false positives by sending benign-oriented payload corpora through a WAF and, when possible, directly to the application origin.

## Recommended run mode

```bash
cp config.example.yaml config.yaml
go run ./cmd/waf-fp --config config.yaml
```

The recommended payload input is a normalized JSONL corpus:

```json
{"id":"benign-ui-0001","value":"Select a delivery method","category":"sqli-like","source":"external-corpus","source_reference":"dataset/item-42","description":"Ordinary UI phrase","tags":["business-text","sql-keyword"]}
```

Only `id` and `value` are required. `source`, `source_reference`, `category`, `description`, and `tags` are retained to make post-run analysis easier. Legacy text payload files remain supported.

## Workflow

The tool does not require manual approval of every payload before execution:

```text
external sources -> normalized corpus -> test run -> review only actionable results
```

The generated summary contains a post-run review queue with blocked, unstable, ambiguous, and route-different requests. Payloads that pass without interesting behavior do not require manual review.

## Evidence model

### Differential mode

The same request is sent through the WAF route and directly to the origin. A reproducible block through the WAF route while the direct origin does not block the request is classified as `CONFIRMED_FP`.

A `403` response alone does not identify which component generated it. If both routes appear blocked, the result is `AMBIGUOUS`.

### WAF-only mode

When direct-origin access is unavailable:

- a reproducible configured block signal is `BLOCKED_BENIGN_CANDIDATE`;
- no configured block signal is `NOT_BLOCKED`;
- the result is reviewed after execution rather than pre-approved before the run.

WAF-only results are useful for triage, but they are not counted as confirmed FP in baseline comparison because the response cannot be attributed to the WAF by route comparison.

## Optional block indicators

The project is product-neutral and does not assume vendor-specific headers or response markers.

```yaml
detection:
  block_statuses: [403, 406]
  block_body_contains: []
  block_body_regex: []
  block_header_contains: []
```

Body and header indicators are optional installation-specific signals. Configure them only when they are actually known for the tested environment.

## Reports and baseline comparison

```yaml
output:
  file: results.jsonl
  summary: summary.md
  baseline: baseline.jsonl
  comparison: comparison.md
  fail_on_new_fp: false
```

The summary groups all results by verdict and placement, then lists an actionable post-run review queue with payload provenance.

Baseline comparison reports:

- `NEW_FP`;
- `FIXED_FP`;
- `UNCHANGED_FP`;
- `NEW_RESPONSE_DIFFERENCE`.

Only `CONFIRMED_FP` is counted as an FP for baseline and CI failure purposes. `BLOCKED_BENIGN_CANDIDATE` remains visible for post-run analysis but does not fail CI as a proven FP.

## Current verdicts

- `CONFIRMED_FP`: direct origin does not block while the WAF route reproducibly blocks;
- `BLOCKED_BENIGN_CANDIDATE`: reproducible block in WAF-only mode;
- `FLAKY_FP`: candidate behavior was not reproduced consistently;
- `RESPONSE_DIFFERENCE`: routes differ without a clear one-sided block;
- `AMBIGUOUS`: both routes appear blocked;
- `NOT_FP` / `NOT_BLOCKED`;
- `WAF_ERROR` / `ORIGIN_ERROR`.

## Next milestones

1. Add corpus import commands that normalize external sources and preserve provenance.
2. Import selected public FP/negative-test corpora without requiring pre-run approval.
3. Improve post-run triage with analyst disposition and notes for actionable results.
4. Add application profiles and authentication support.
5. Expand request structures: multipart, XML, GraphQL, nested JSON, repeated parameters, and encodings.
