# waf-fp-test

`waf-fp-test` searches for WAF false positives by sending benign-oriented payload corpora through a WAF and, when possible, directly to the application origin.

## What is a corpus?

A corpus is the prepared set of values that the runner will place into query parameters, JSON, forms, headers, cookies, and paths.

A plain text corpus can contain one payload per line:

```text
Select a delivery method
The trade union published its annual report
Use ../docs as the relative documentation path
```

The recommended normalized form is JSONL because every payload can also carry a stable ID and provenance:

```json
{"id":"corpus-6ab8c97eb91c52b4","value":"Select a delivery method","category":"sqli-like","source":"public-negative-tests","source_reference":"repository/path@version","tags":["business-text"]}
```

Only `id` and `value` are required by the runner. The other fields exist to make post-run analysis easier.

## Importing external corpora

Use `corpus-import` to convert external files into normalized JSONL:

```bash
go run ./cmd/corpus-import \
  --input external-payloads.txt \
  --output corpora/external.jsonl \
  --source public-negative-tests \
  --source-reference repository/path@version \
  --category sqli-like \
  --tags external,negative-test
```

Supported input formats:

- TXT: one payload per non-empty, non-comment line;
- CSV: first column by default, or a named column through `--value-field`;
- JSON: array of strings or array of objects;
- JSONL/NDJSON: strings or objects per line;
- YAML: a simple scalar list where every payload line starts with `-`.

Examples:

```bash
# CSV with a column named payload
go run ./cmd/corpus-import \
  --input input.csv \
  --value-field payload \
  --source vendor-dataset \
  --output corpus.jsonl

# JSON objects using a field named test_string
go run ./cmd/corpus-import \
  --input input.json \
  --value-field test_string \
  --source public-project \
  --output corpus.jsonl
```

The importer:

- removes empty values and comments from text inputs;
- removes exact duplicates within the imported file;
- generates deterministic IDs from `source + payload value`;
- preserves source, source reference, category, and tags;
- reports how many records were read, written, skipped, and deduplicated.

It does not decide whether a payload is a real FP. It only prepares the input corpus. FP analysis happens after the runner sends the requests.

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

1. Import selected public FP/negative-test corpora without requiring pre-run approval.
2. Improve post-run triage with analyst disposition and notes for actionable results.
3. Add application profiles and authentication support.
4. Expand request structures: multipart, XML, GraphQL, nested JSON, repeated parameters, and encodings.
