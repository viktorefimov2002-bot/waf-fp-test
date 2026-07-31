# waf-fp-test

`waf-fp-test` is an early-stage framework for detecting WAF false positives by comparing the same benign request through a WAF and directly against the origin.

## Current prototype

The current stage implements:

- benign payloads loaded from a text file;
- a controlled placement matrix: query, form, JSON, header, cookie, and path;
- a request through the WAF and a direct-origin baseline request;
- `X-WAF-FP-Test-ID` correlation IDs;
- configurable blocking status codes;
- automatic rechecks for candidate false positives;
- JSONL results containing every attempt;
- verdicts: `CONFIRMED_FP`, `FLAKY_FP`, `NOT_FP`, `AMBIGUOUS`, `WAF_ERROR`, and `ORIGIN_ERROR`;
- Go tests and GitHub Actions CI.

## Run

```bash
go run ./cmd/waf-fp \
  --target https://waf.example.test \
  --origin http://10.0.0.20:8080 \
  --path /anything \
  --payloads examples/payloads.txt \
  --placements query,form,json,header,cookie,path \
  --rechecks 2 \
  --block-statuses 403,406 \
  --output results.jsonl
```

A candidate found on the first attempt is checked two more times by default. It remains `CONFIRMED_FP` only when all attempts reproduce the same WAF-only block; otherwise it is marked `FLAKY_FP`.

Only run tests against systems you own or are explicitly authorized to test.

## Why request diversity matters for false positives

Diversity is important because WAF rules inspect different request collections and parsing paths. The same benign value can pass in a query parameter but be blocked in JSON, a cookie, a header, or a path segment.

The goal is not uncontrolled random traffic. The project uses a reproducible test matrix:

```text
benign payload × placement × content type × encoding × method
```

The current matrix deliberately changes one principal dimension at a time. That makes findings explainable and suitable for regression testing instead of producing a large set of opaque random requests.

## Current placements

| Placement | Method | Representation |
|---|---:|---|
| `query` | GET | `fp_param=<payload>` |
| `form` | POST | `application/x-www-form-urlencoded` |
| `json` | POST | `{"fp_param":"<payload>"}` |
| `header` | GET | `X-WAF-FP-Value` |
| `cookie` | GET | cookie `fp_param` |
| `path` | GET | appended path segment |

## Next milestones

1. Add an echo-origin container that records correlation IDs and parsed request details.
2. Import and normalize false-positive corpora with provenance and categories.
3. Add result summaries and baseline comparison.
4. Add multipart and XML placements.
5. Add controlled encoding variants.
