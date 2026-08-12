# waf-fp-test

`waf-fp-test` sends false-positive payload corpora through a WAF and, when possible, directly to the application origin. The primary ready-made source is `mgm-sp/WAF-Payload-Collection`; the project collects its `nuclei/payloads/*/false-positives.txt` files automatically and does not generate new payloads.

## Requirements

- Go 1.23 or newer;
- Git available in `PATH`;
- network access to clone the public payload repository;
- a WAF-protected test URL;
- for high-confidence `CONFIRMED_FP` results, direct access to the same origin endpoint.

## 1. Clone and check the project

```bash
git clone https://github.com/viktorefimov2002-bot/waf-fp-test.git
cd waf-fp-test
go test ./...
go build ./cmd/waf-fp
go build ./cmd/corpus-import
go build ./cmd/corpus-sync-mgm
```

When working before PR #2 is merged, check out its branch:

```bash
git switch agent/reporting-baseline
```

## 2. Download and prepare the MGM FP corpora

Run:

```bash
go run ./cmd/corpus-sync-mgm
```

The command:

1. clones `https://github.com/mgm-sp/WAF-Payload-Collection.git` into `sources/WAF-Payload-Collection`, or fetches updates when the checkout already exists;
2. recursively finds `nuclei/payloads/*/false-positives.txt`;
3. treats each non-empty, non-comment line as one existing FP payload;
4. derives the category from the parent directory, such as `cmdexe`, `sqli`, `xss`, or `traversal`;
5. removes exact duplicates across the collected source files;
6. creates stable IDs and preserves the source file path;
7. writes a combined corpus and one corpus per category.

Generated files:

```text
corpora/mgm/
├── all.jsonl
├── cmdexe.jsonl
├── sqli.jsonl
├── xss.jsonl
└── ...
```

A generated entry looks like:

```json
{"id":"mgm-cmdexe-...","value":"curl and divergence","category":"cmdexe","source":"mgm-sp/WAF-Payload-Collection","source_reference":"nuclei/payloads/cmdexe/false-positives.txt","tags":["false-positive","cmdexe"]}
```

No payload text is invented or modified beyond trimming surrounding whitespace.

### Reproducible source version

Pin a tag, branch, or commit:

```bash
go run ./cmd/corpus-sync-mgm \
  --revision eb606fd212c7a00edb95666e150c0044a217aa44
```

Useful overrides:

```bash
go run ./cmd/corpus-sync-mgm \
  --repository https://github.com/mgm-sp/WAF-Payload-Collection.git \
  --work-dir sources/WAF-Payload-Collection \
  --output-dir corpora/mgm
```

## 3. Configure the WAF test

Create a working configuration:

```bash
cp config.example.yaml config.yaml
```

Use the generated combined corpus:

```yaml
mode: differential

target:
  url: https://waf-test.example
  path: /fp-test

origin:
  url: https://192.0.2.10:443
  host: waf-test.example
  sni: waf-test.example

request:
  payloads: corpora/mgm/all.jsonl
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

Use a category corpus for a narrower run:

```yaml
request:
  payloads: corpora/mgm/sqli.jsonl
```

## 4. Run the tests

```bash
go run ./cmd/waf-fp --config config.yaml
```

Each corpus value is tested in every configured placement. For example, six placements produce six requests per payload.

Outputs:

- `results.jsonl`: complete machine-readable observations and verdicts;
- `summary.md`: counts and the post-run review queue;
- `comparison.md`: changes against a baseline, when configured.

## 5. Interpret the verdicts

### Differential mode

The same request is sent through the WAF and directly to the origin.

- `CONFIRMED_FP`: WAF route reproducibly blocks while the direct-origin route does not;
- `AMBIGUOUS`: both routes appear blocked;
- `RESPONSE_DIFFERENCE`: routes differ without a clear one-sided block;
- `NOT_FP`: no FP evidence was observed;
- `WAF_ERROR` / `ORIGIN_ERROR`: execution problem.

### WAF-only mode

Use this only when direct-origin access is unavailable:

```yaml
mode: waf-only
```

- `BLOCKED_BENIGN_CANDIDATE`: a configured block signal was reproduced;
- `NOT_BLOCKED`: no configured block signal was observed.

A WAF-only block is placed in the review queue but is not counted as a confirmed FP because a status such as `403` does not identify which component generated it.

## 6. Baseline comparison

After accepting a run as a baseline:

```bash
cp results.jsonl baseline.jsonl
```

Configure the next run:

```yaml
output:
  baseline: baseline.jsonl
  comparison: comparison.md
  fail_on_new_fp: true
```

The comparison reports `NEW_FP`, `FIXED_FP`, `UNCHANGED_FP`, and `NEW_RESPONSE_DIFFERENCE`. Only `CONFIRMED_FP` counts as an FP for CI failure purposes.

## Importing other or custom files

The generic importer remains available for existing TXT, CSV, JSON, JSONL, and simple YAML lists:

```bash
go run ./cmd/corpus-import \
  --input my-existing-fp.txt \
  --output corpora/custom.jsonl \
  --source internal \
  --category custom
```

This is an optional extension. The default initial workflow uses only the existing MGM payload files.

## Current limitations and remaining work

The project is usable for an initial black-box run, but it is not feature-complete:

1. Request construction currently uses a generic endpoint and parameter name (`fp_param`); application-specific request profiles are not implemented.
2. Authentication, session bootstrap, custom headers, and CSRF token handling are not implemented.
3. Placements are basic: query, form, flat JSON, one header, one cookie, and path. Multipart, XML, GraphQL, nested JSON, arrays, repeated parameters, and encoding matrices remain to be added.
4. A control request that validates each endpoint/method before the corpus run is not automated yet.
5. Post-run analyst dispositions such as confirmed, rejected, application block, and notes are not persisted yet.
6. Source updates are fetched from the external repository, but the generated corpus itself is not automatically committed or versioned.
7. End-to-end integration tests against a controlled echo origin and a real WAF test deployment are still required.

The recommended next stage is to add request/application profiles and an automated control request, then execute the first real MGM corpus run against the test WAF.
