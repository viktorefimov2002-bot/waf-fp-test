# waf-fp-test

`waf-fp-test` detects WAF false positives by sending reviewed benign requests through a WAF and, when possible, directly to the application origin.

## Recommended run mode

```bash
cp config.example.yaml config.yaml
go run ./cmd/waf-fp --config config.yaml
```

The recommended payload input is a normalized JSONL corpus:

```json
{"id":"benign-ui-0001","value":"Select a delivery method","category":"sqli-like","source":"internal-review","source_reference":"starter-corpus","legitimacy":"verified","review_status":"approved","description":"Ordinary UI phrase","tags":["business-text","sql-keyword"]}
```

Legacy text payload files remain supported, but their entries are automatically treated as `candidate` / `pending` because they do not carry review metadata.

## Evidence model

The tool separates three questions:

1. Is the payload reviewed and known to be benign?
2. Is the request context valid for the tested endpoint?
3. Can the response be attributed to the WAF by comparing the WAF route with a direct-origin route?

### Differential mode

A request is sent through the WAF and directly to the origin. A reproducible block through the WAF route while the direct origin accepts the same request is classified as `CONFIRMED_FP`.

A `403` response alone does not prove which component generated it. If both routes return a block response, the result is `AMBIGUOUS`.

### WAF-only mode

When direct-origin access is unavailable:

- `LIKELY_FP` requires an entry with `legitimacy: verified`, `review_status: approved`, a manually validated request context, a reproducible block signal, and no direct-origin evidence;
- `BLOCKED_BENIGN_CANDIDATE` is used when the payload or request context has not been fully reviewed;
- `NOT_BLOCKED` means no configured block signal was observed.

A request context is marked explicitly:

```yaml
request:
  payloads: examples/corpus.jsonl
  context_verified: true
```

or through CLI:

```bash
go run ./cmd/waf-fp --config config.yaml --request-context-verified
```

This setting must only be enabled after checking that the endpoint, method, parameter placement, authentication state, and control request are valid.

## Optional block indicators

The project is product-neutral and does not assume any vendor-specific headers or response markers.

```yaml
detection:
  block_statuses: [403, 406]
  block_body_contains: []
  block_body_regex: []
  block_header_contains: []
```

Body and header indicators are optional installation-specific signals. Configure them only when they have been verified in the tested environment.

## Reports and baseline comparison

```yaml
output:
  file: results.jsonl
  summary: summary.md
  baseline: baseline.jsonl
  comparison: comparison.md
  fail_on_new_fp: false
```

The summary groups results by verdict and placement and includes payload provenance. Baseline comparison reports `NEW_FP`, `FIXED_FP`, `UNCHANGED_FP`, and `NEW_RESPONSE_DIFFERENCE`.

For baseline purposes, only `CONFIRMED_FP` and `LIKELY_FP` are treated as FP verdicts. `BLOCKED_BENIGN_CANDIDATE` remains actionable but is not counted as a proven or likely FP.

## Current verdicts

- `CONFIRMED_FP`: direct origin accepts the request while the WAF route reproducibly blocks it;
- `LIKELY_FP`: verified benign payload and valid request context are reproducibly blocked in WAF-only mode;
- `BLOCKED_BENIGN_CANDIDATE`: benign-looking or unreviewed evidence is blocked, but the evidence level is incomplete;
- `FLAKY_FP`: candidate behavior was not reproduced consistently;
- `RESPONSE_DIFFERENCE`: routes differ without a clear block signal;
- `AMBIGUOUS`: both routes appear blocked;
- `NOT_FP` / `NOT_BLOCKED`;
- `WAF_ERROR` / `ORIGIN_ERROR`.

## Corpus review workflow

External datasets must first be imported as `candidate` / `pending`. They become `verified` / `approved` only after manual review confirms that the value is benign and the provenance is recorded.

```text
external source -> candidate/pending -> manual review -> verified/approved
```

The initial normalized corpus and loader are now in place. The next implementation stage is an importer/review command that converts external source formats into JSONL without automatically trusting them.

## Next milestones

1. Add corpus import and review commands while preserving provenance.
2. Import selected external false-positive corpora as `candidate/pending`.
3. Add application profiles and authentication support.
4. Expand request structures: multipart, XML, GraphQL, nested JSON, repeated parameters, and encodings.
5. Add an optional echo-origin for controlled integration tests.
