# Optional rule correlation

`waf-fp-test` can be used without WAF logs, Rule IDs, or an integration with a log storage system. The runner records the request test ID in `X-WAF-FP-Test-ID` and produces `results.jsonl` independently.

When rule metadata becomes available later, use `results-annotate` to attach it without changing the original results.

## Annotation file

Create a JSONL file with one annotation per line. An annotation can match one exact result by `test_id`:

```json
{"match":{"test_id":"waf-fp-..."},"rule":{"rule_id":"942100","rule_name":"SQL injection detector","source":"waf-log","notes":"Correlated manually by X-WAF-FP-Test-ID"}}
```

Or it can match a reusable result group by `payload_id`, optionally narrowed by `placement` and future `profile`:

```json
{"match":{"payload_id":"mgm-sqli-d6a23b83af12b926","placement":"json"},"rule":{"rule_id":"942100","matched_field":"ARGS:query","matched_data":"union was a great select","source":"manual-log-correlation"}}
```

At least one of `test_id` or `payload_id` is required. At least one of `rule_id`, `rule_name`, or `rule_text` is required.

Supported rule metadata fields:

- `rule_id`;
- `rule_name`;
- `rule_text`;
- `matched_field`;
- `matched_data`;
- `source`;
- `notes`;
- `tags`.

A complete copied Seclang rule may be stored in `rule_text` when no Rule ID is known.

## Run

```bash
go run ./cmd/results-annotate \
  --results results.jsonl \
  --annotations rule-annotations.jsonl \
  --output results.enriched.jsonl \
  --report rule-annotations.md
```

The command does not overwrite `results.jsonl`. It creates:

- `results.enriched.jsonl`, where matching records contain `rule_metadata`;
- `rule-annotations.md`, a concise table of the applied links.

It also reports annotations that did not match any result. This is useful for detecting stale test IDs, incorrect placements, or payload IDs from another corpus version.

## Recommended workflow

```text
run corpus
-> review confirmed FP
-> search WAF logs by X-WAF-FP-Test-ID when possible
-> otherwise correlate manually
-> write rule-annotations.jsonl
-> generate enriched results
-> prepare a scoped exclusion recommendation
```

Rule metadata is optional. Without it, the project can still detect and reproduce WAF/origin differences, but it should not claim that a specific Seclang rule caused the block.
